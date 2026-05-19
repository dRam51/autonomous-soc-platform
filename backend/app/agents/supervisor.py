"""
Supervisor Agent — Orchestrates the full SOC agent pipeline via LangGraph.

Flow:
  alert_in → triage → threat_intel → investigation → remediation → reporting → END
"""

from typing import TypedDict, Annotated, Optional
from langgraph.graph import StateGraph, END
from app.agents.triage import run_triage
from app.agents.threat_intel import run_threat_intel
from app.agents.investigation import run_investigation
from app.agents.remediation import run_remediation
from app.agents.reporting import run_reporting
from app.models.schemas import (
    AlertCreate,
    TriageResult,
    ThreatIntelResult,
    InvestigationResult,
    RemediationResult,
    IncidentReport,
)
import logging

logger = logging.getLogger(__name__)


class SOCState(TypedDict):
    alert_id: str
    alert: AlertCreate
    triage: Optional[TriageResult]
    threat_intel: Optional[ThreatIntelResult]
    investigation: Optional[InvestigationResult]
    remediation: Optional[RemediationResult]
    incident_report: Optional[IncidentReport]
    error: Optional[str]


def should_escalate(state: SOCState) -> str:
    """
    Routing logic: only escalate to full investigation if severity warrants it.
    Low/Info alerts skip investigation and go straight to remediation.
    """
    triage = state.get("triage")
    if triage and triage.severity in ("critical", "high", "medium"):
        return "investigate"
    return "remediate"


def build_soc_graph() -> StateGraph:
    graph = StateGraph(SOCState)

    graph.add_node("triage", run_triage)
    graph.add_node("threat_intel", run_threat_intel)
    graph.add_node("investigation", run_investigation)
    graph.add_node("remediation", run_remediation)
    graph.add_node("reporting", run_reporting)

    graph.set_entry_point("triage")

    graph.add_edge("triage", "threat_intel")
    graph.add_conditional_edges(
        "threat_intel",
        should_escalate,
        {"investigate": "investigation", "remediate": "remediation"},
    )
    graph.add_edge("investigation", "remediation")
    graph.add_edge("remediation", "reporting")
    graph.add_edge("reporting", END)

    return graph.compile()


soc_graph = build_soc_graph()


async def process_alert(alert_id: str, alert: AlertCreate) -> IncidentReport:
    """Entry point: run the full multi-agent pipeline for a given alert."""
    logger.info(f"[Supervisor] Starting pipeline for alert {alert_id}")

    initial_state: SOCState = {
        "alert_id": alert_id,
        "alert": alert,
        "triage": None,
        "threat_intel": None,
        "investigation": None,
        "remediation": None,
        "incident_report": None,
        "error": None,
    }

    final_state = await soc_graph.ainvoke(initial_state)

    if final_state.get("error"):
        raise RuntimeError(f"Pipeline failed: {final_state['error']}")

    return final_state["incident_report"]
