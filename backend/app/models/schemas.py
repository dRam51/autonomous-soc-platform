"""
Pydantic Data Models

These schemas define the shape of data flowing through the entire pipeline:
from the inbound alert submitted by a SIEM, through each agent's output,
to the final incident report returned to the analyst.

Pydantic validates every field at instantiation time, raising clear errors
if a required field is missing or if a confidence score is outside [0,1].
Using typed schemas (rather than plain dicts) also makes the pipeline's data
contract explicit: each agent knows exactly what fields prior agents produced.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
from datetime import datetime


# === Enums ===

class SeverityLevel(str, Enum):
    """Five-tier severity scale aligned with standard SOC classification.

    Using str as a base class means severity values serialize to their string
    form ("critical", "high") in JSON rather than integers. This makes API
    responses human-readable without extra serialization logic.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Tracks where an alert is in the pipeline lifecycle.

    These status values are what the SSE stream and frontend use to show
    real-time pipeline progress. The transition path for a normal alert is:
    NEW -> TRIAGING -> CLOSED. HITL-paused alerts stay at TRIAGING until approved.
    """
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    REMEDIATING = "remediating"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, Enum):
    """Incident lifecycle status, separate from alert pipeline status.

    An alert's pipeline can be CLOSED (all agents ran) while the incident it
    produced is still OPEN (analysts haven't resolved the underlying threat).
    """
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


# === Alert Schemas ===

class AlertCreate(BaseModel):
    """The inbound payload submitted by a SIEM, EDR, or analyst.

    Only title, description, and source are required. All other fields are
    optional because not every alert has an associated IP or IOC. Agents
    handle missing optional fields gracefully with "Unknown" fallbacks.
    """
    title: str
    description: str
    source: str = Field(..., description="Source system e.g. SIEM, EDR, IDS")
    raw_log: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_host: Optional[str] = None
    iocs: Optional[List[str]] = Field(default=[], description="Indicators of compromise")


class AlertResponse(AlertCreate):
    """Extends AlertCreate with server-assigned fields returned by the API.

    from_attributes=True allows creating an AlertResponse from an ORM model
    instance (SQLAlchemy row) when PostgreSQL integration is added.
    """
    id: str
    severity: Optional[SeverityLevel] = None  # Populated after triage completes
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# === Agent Output Schemas ===

class TriageResult(BaseModel):
    """Output of the Triage agent: severity classification and reasoning."""
    alert_id: str
    severity: SeverityLevel
    # ge/le constraints on confidence enforce the 0.0-1.0 range at the schema level,
    # so downstream consumers can rely on this invariant without defensive checks.
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    recommended_action: str
    mitre_techniques: List[str] = []


class ThreatIntelResult(BaseModel):
    """Output of the Threat Intel agent: external enrichment from OSINT tools."""
    alert_id: str
    related_cves: List[str] = []
    mitre_tactics: List[str] = []
    threat_actors: List[str] = []
    ioc_analysis: str
    # 0.0-10.0 mirrors CVSS scoring so analysts have an intuitive reference point.
    risk_score: float = Field(..., ge=0.0, le=10.0)


class InvestigationResult(BaseModel):
    """Output of the Investigation agent: deep-dive analysis and attack reconstruction."""
    alert_id: str
    timeline: List[dict] = []            # Ordered list of {timestamp, event} dicts
    attack_chain: str                    # Narrative description of the attack progression
    affected_assets: List[str] = []
    lateral_movement_detected: bool = False
    data_exfiltration_risk: bool = False
    full_analysis: str                   # Comprehensive investigation narrative


class RemediationResult(BaseModel):
    """Output of the Remediation agent: structured response playbook.

    The three-tier structure mirrors NIST IR phases:
      immediate_actions = Containment
      short_term_actions = Eradication + Recovery
      long_term_recommendations = Post-Incident Hardening
    """
    alert_id: str
    immediate_actions: List[str] = []
    short_term_actions: List[str] = []
    long_term_recommendations: List[str] = []
    playbook_reference: Optional[str] = None   # e.g., "IRP-042: Ransomware Response"
    estimated_effort: str


# === Incident Schemas ===

class IncidentReport(BaseModel):
    """
    The final consolidated output of the entire multi-agent pipeline.
    All four agent results are embedded here so the API returns everything
    in a single response rather than requiring four separate API calls.

    Agent outputs are Optional because:
    - Triage is always present (required for any incident to exist)
    - Threat intel may be None if that agent failed
    - Investigation is None for low/info severity alerts (they skip the investigation node)
    - Remediation is always present once the pipeline completes
    """
    incident_id: str
    alert_id: str
    title: str
    executive_summary: str             # Generated by the Reporting agent (claude-haiku)
    severity: SeverityLevel
    status: IncidentStatus
    triage: Optional[TriageResult] = None
    threat_intel: Optional[ThreatIntelResult] = None
    investigation: Optional[InvestigationResult] = None
    remediation: Optional[RemediationResult] = None
    created_at: datetime
    updated_at: datetime
