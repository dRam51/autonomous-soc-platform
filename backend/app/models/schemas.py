from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
from datetime import datetime


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    REMEDIATING = "remediating"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ─── Alert Schemas ───────────────────────────────────────

class AlertCreate(BaseModel):
    title: str
    description: str
    source: str = Field(..., description="Source system e.g. SIEM, EDR, IDS")
    raw_log: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_host: Optional[str] = None
    iocs: Optional[List[str]] = Field(default=[], description="Indicators of compromise")


class AlertResponse(AlertCreate):
    id: str
    severity: Optional[SeverityLevel] = None
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ─── Agent Output Schemas ─────────────────────────────────

class TriageResult(BaseModel):
    alert_id: str
    severity: SeverityLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    recommended_action: str
    mitre_techniques: List[str] = []


class ThreatIntelResult(BaseModel):
    alert_id: str
    related_cves: List[str] = []
    mitre_tactics: List[str] = []
    threat_actors: List[str] = []
    ioc_analysis: str
    risk_score: float = Field(..., ge=0.0, le=10.0)


class InvestigationResult(BaseModel):
    alert_id: str
    timeline: List[dict] = []
    attack_chain: str
    affected_assets: List[str] = []
    lateral_movement_detected: bool = False
    data_exfiltration_risk: bool = False
    full_analysis: str


class RemediationResult(BaseModel):
    alert_id: str
    immediate_actions: List[str] = []
    short_term_actions: List[str] = []
    long_term_recommendations: List[str] = []
    playbook_reference: Optional[str] = None
    estimated_effort: str


# ─── Incident Schemas ─────────────────────────────────────

class IncidentReport(BaseModel):
    incident_id: str
    alert_id: str
    title: str
    executive_summary: str
    severity: SeverityLevel
    status: IncidentStatus
    triage: Optional[TriageResult] = None
    threat_intel: Optional[ThreatIntelResult] = None
    investigation: Optional[InvestigationResult] = None
    remediation: Optional[RemediationResult] = None
    created_at: datetime
    updated_at: datetime
