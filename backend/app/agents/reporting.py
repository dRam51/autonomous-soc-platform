"""
Reporting Agent

Techniques implemented:
  - Prompt caching: system prompt cached
  - Agent memory: writes incident outcome back to memory store for future agents
  - Confidence calibration: attaches overall pipeline confidence to the report
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import IncidentReport, IncidentStatus
from app.core.memory import store_memory
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

REPORTING_SYSTEM_PROMPT = """You are a cybersecurity incident report writer.

Given all findings from a SOC investigation, write a clear executive summary that:
1. Describes what happened in plain language for a non-technical audience
2. Conveys business impact and risk clearly
3. Summarizes the response actions being taken
4. Is concise (3-5 sentences maximum)

The technical details are captured separately. Focus on clarity and business relevance."""


async def run_reporting(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]
    threat_intel = state["threat_intel"]
    investigation = state.get("investigation")
    remediation = state["remediation"]

    logger.info(f"[Reporting] Compiling incident report for alert {alert_id}")

    # Confidence calibration: compute overall pipeline confidence
    # weighted average of triage confidence and risk_score normalization
    triage_conf = triage.confidence
    risk_normalized = threat_intel.risk_score / 10.0
    overall_confidence = round((triage_conf * 0.6) + (risk_normalized * 0.4), 3)

    prompt = f"""Write an executive summary for this security incident.

Incident: {alert.title}
Severity: {triage.severity.upper()}
Risk Score: {threat_intel.risk_score}/10
Overall Pipeline Confidence: {overall_confidence:.0%}
Attack Techniques: {', '.join(triage.mitre_techniques)}
Affected Assets: {', '.join(investigation.affected_assets) if investigation else alert.affected_host or 'Unknown'}
Lateral Movement: {investigation.lateral_movement_detected if investigation else 'Unknown'}
Exfiltration Risk: {investigation.data_exfiltration_risk if investigation else 'Unknown'}
Key Immediate Actions: {'; '.join(remediation.immediate_actions[:2])}

Write a 3-5 sentence executive summary suitable for a CISO or non-technical stakeholder."""

    response = await client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=512,
        system=[
            {
                "type": "text",
                "text": REPORTING_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": prompt}],
    )

    executive_summary = response.content[0].text
    incident_id = str(uuid.uuid4())

    incident_report = IncidentReport(
        incident_id=incident_id,
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

    # Write outcomes back to agent memory for future incidents
    entities_to_remember = []
    if alert.source_ip:
        entities_to_remember.append(("ip", alert.source_ip))
    if alert.destination_ip:
        entities_to_remember.append(("ip", alert.destination_ip))
    if alert.affected_host:
        entities_to_remember.append(("host", alert.affected_host))

    memory_summary = (
        f"{triage.severity.upper()} incident: {alert.title[:100]}. "
        f"Risk score {threat_intel.risk_score}/10. "
        f"TTPs: {', '.join(triage.mitre_techniques[:3])}."
    )

    for entity_type, entity_value in entities_to_remember:
        await store_memory(
            entity_type=entity_type,
            entity_value=entity_value,
            incident_id=incident_id,
            severity=triage.severity.value,
            summary=memory_summary,
            iocs=alert.iocs,
            mitre_techniques=triage.mitre_techniques,
        )

    logger.info(
        f"[Reporting] Incident {incident_id} compiled. "
        f"Confidence={overall_confidence:.0%}. Memory updated for {len(entities_to_remember)} entities."
    )
    return {**state, "incident_report": incident_report}
