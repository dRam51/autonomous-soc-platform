"""
Reporting Agent — Compiles all agent outputs into a structured Incident Report.
Produces both a technical report and an executive summary.
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import IncidentReport, IncidentStatus
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

REPORTING_SYSTEM_PROMPT = """You are a cybersecurity incident report writer.

Given all findings from a SOC investigation, write a clear executive summary that:
1. Describes what happened in plain English (non-technical audience)
2. Conveys business impact and risk
3. Summarizes what's being done about it
4. Is concise (3-5 sentences max)

The technical details are captured separately — focus on clarity and business relevance."""


async def run_reporting(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]
    threat_intel = state["threat_intel"]
    investigation = state.get("investigation")
    remediation = state["remediation"]

    logger.info(f"[Reporting] Compiling incident report for alert {alert_id}")

    prompt = f"""Write an executive summary for this security incident.

Incident: {alert.title}
Severity: {triage.severity.upper()}
Risk Score: {threat_intel.risk_score}/10
Attack Techniques: {', '.join(triage.mitre_techniques)}
Affected Assets: {', '.join(investigation.affected_assets) if investigation else alert.affected_host or 'Unknown'}
Immediate Actions Taken: {'; '.join(remediation.immediate_actions[:2])}

Write a 3-5 sentence executive summary suitable for a CISO or non-technical stakeholder."""

    response = await client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=512,
        system=REPORTING_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    executive_summary = response.content[0].text

    incident_report = IncidentReport(
        incident_id=str(uuid.uuid4()),
        alert_id=alert_id,
        title=f"[{triage.severity.upper()}] {alert.title}",
        executive_summary=executive_summary,
        severity=triage.severity,
        status=IncidentStatus.OPEN,
        triage=triage,
        threat_intel=threat_intel,
        investigation=investigation,
        remediation=remediation,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    logger.info(f"[Reporting] Incident report {incident_report.incident_id} compiled")
    return {**state, "incident_report": incident_report}
