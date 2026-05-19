"""
Supervisor Agent - LangGraph Orchestrator

Techniques implemented:
  - Parallel agent execution: threat_intel and ip_intel run simultaneously after triage
  - Human-in-the-loop: LangGraph interrupt() pauses pipeline on CRITICAL alerts
    for analyst approval before remediation executes
  - Conditional routing: low/info severity skips investigation
  - Stateful graph: shared SOCState carries all context between agents
"""

from typing import TypedDict, Optional, Annotated
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.errors import NodeInterrupt
from app.agents.triage import run_triage
from app.agents.threat_intel import run_threat_intel
from app.agents.investigation import run_investigation
from app.agents.remediation import run_remediation
from app.agents.reporting import run_reporting
from app.skills.ip_intel import geolocate_ip
from app.models.schemas import (
    AlertCreate, TriageResult, ThreatIntelResult,
    InvestigationResult, RemediationResult, IncidentReport,
)
from app.config import settings
import asyncio
import logging

logger = logging.getLogger(__name__)


class SOCState(TypedDict):
    alert_id: str
    alert: AlertCreate
    triage: Optional[TriageResult]
    threat_intel: Optional[ThreatIntelResult]
    ip_context: Optional[str]              # IP geolocation result (parallel with threat_intel)
    investigation: Optional[InvestigationResult]
    remediation: Optional[RemediationResult]
    incident_report: Optional[IncidentReport]
    hitl_approved: Optional[bool]          # Human-in-the-loop approval flag
    anomaly_score: Optional[float]
    error: Optional[str]


# ─── Parallel enrichment node ─────────────────────────────────────────────────

async def run_parallel_enrichment(state: SOCState) -> SOCState:
    """
    Runs threat_intel and IP geolocation in parallel after triage completes.
    Both depend only on triage output, not on each other.

    This is the parallel execution technique:
      Instead of: triage -> threat_intel -> ip_geolocate (sequential)
      We get:     triage -> [threat_intel || ip_geolocate] -> investigation (parallel)
    """
    alert = state["alert"]

    # Build parallel tasks
    threat_intel_task = run_threat_intel(state)

    ip_task = None
    if alert.source_ip or alert.destination_ip:
        ip_to_check = alert.source_ip or alert.destination_ip
        ip_task = geolocate_ip(ip_to_check)

    if ip_task:
        threat_intel_result, ip_result = await asyncio.gather(
            threat_intel_task,
            ip_task,
            return_exceptions=True,
        )
        ip_context = ip_result if isinstance(ip_result, str) else "IP geolocation failed"
    else:
        threat_intel_result = await threat_intel_task
        ip_context = "No IP addresses to geolocate"

    # Merge results back into state
    new_state = threat_intel_result if isinstance(threat_intel_result, dict) else state
    return {**new_state, "ip_context": ip_context}


# ─── Human-in-the-loop node ───────────────────────────────────────────────────

async def hitl_approval_gate(state: SOCState) -> SOCState:
    """
    Human-in-the-loop checkpoint for CRITICAL severity alerts.

    If HITL is enabled and severity is CRITICAL, this node raises NodeInterrupt,
    which pauses the LangGraph execution and persists state to the checkpointer.
    The pipeline resumes when an analyst calls resume_pipeline() via the API.

    If HITL is disabled (e.g. in development), it auto-approves.
    """
    triage = state.get("triage")
    if not triage:
        return state

    is_critical = triage.severity.value == "critical"

    if is_critical and settings.enable_hitl and not state.get("hitl_approved"):
        logger.info(
            f"[Supervisor] CRITICAL alert {state['alert_id']} paused for human approval"
        )
        raise NodeInterrupt(
            f"CRITICAL alert requires analyst approval before remediation. "
            f"Alert ID: {state['alert_id']}. "
            f"Severity: {triage.severity}. "
            f"Call POST /api/v1/alerts/{state['alert_id']}/approve to continue."
        )

    return {**state, "hitl_approved": True}


# ─── Routing logic ────────────────────────────────────────────────────────────

def should_investigate(state: SOCState) -> str:
    """
    Conditional edge: only escalate to investigation for medium+ severity.
    Low and info alerts skip investigation and go straight to remediation.
    This saves cost and time proportional to actual risk.
    """
    triage = state.get("triage")
    if triage and triage.severity.value in ("critical", "high", "medium"):
        return "investigate"
    return "remediate"


# ─── Graph construction ───────────────────────────────────────────────────────

def build_soc_graph() -> StateGraph:
    """
    Build the LangGraph state machine.

    Flow:
      triage -> parallel_enrichment -> hitl_gate -> [investigate | remediate] -> reporting
    """
    # Use MemorySaver for HITL state persistence (swap for SqliteSaver in production)
    checkpointer = MemorySaver()

    graph = StateGraph(SOCState)

    graph.add_node("triage", run_triage)
    graph.add_node("parallel_enrichment", run_parallel_enrichment)
    graph.add_node("hitl_gate", hitl_approval_gate)
    graph.add_node("investigation", run_investigation)
    graph.add_node("remediation", run_remediation)
    graph.add_node("reporting", run_reporting)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "parallel_enrichment")
    graph.add_edge("parallel_enrichment", "hitl_gate")
    graph.add_conditional_edges(
        "hitl_gate",
        should_investigate,
        {"investigate": "investigation", "remediate": "remediation"},
    )
    graph.add_edge("investigation", "remediation")
    graph.add_edge("remediation", "reporting")
    graph.add_edge("reporting", END)

    return graph.compile(checkpointer=checkpointer, interrupt_before=["hitl_gate"])


soc_graph = build_soc_graph()


async def process_alert(alert_id: str, alert: AlertCreate, anomaly_score: float = 1.0) -> IncidentReport:
    """Entry point: run the full multi-agent SOC pipeline for a given alert."""
    logger.info(f"[Supervisor] Starting pipeline for alert {alert_id}")

    initial_state: SOCState = {
        "alert_id": alert_id,
        "alert": alert,
        "triage": None,
        "threat_intel": None,
        "ip_context": None,
        "investigation": None,
        "remediation": None,
        "incident_report": None,
        "hitl_approved": not settings.enable_hitl,  # Auto-approve when HITL disabled
        "anomaly_score": anomaly_score,
        "error": None,
    }

    config = {"configurable": {"thread_id": alert_id}}
    final_state = await soc_graph.ainvoke(initial_state, config=config)

    if final_state.get("error"):
        raise RuntimeError(f"Pipeline failed: {final_state['error']}")

    return final_state["incident_report"]


async def resume_pipeline(alert_id: str) -> IncidentReport:
    """
    Resume a HITL-paused pipeline after analyst approval.
    Called by the API when an analyst approves a CRITICAL alert.
    """
    logger.info(f"[Supervisor] Resuming HITL-paused pipeline for alert {alert_id}")
    config = {"configurable": {"thread_id": alert_id}}

    # Update state with approval and resume
    update = {"hitl_approved": True}
    final_state = await soc_graph.ainvoke(update, config=config)

    if final_state.get("error"):
        raise RuntimeError(f"Resumed pipeline failed: {final_state['error']}")

    return final_state["incident_report"]
