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

# === System Prompt ===

# The reporting agent uses claude-haiku-4-5 (the fastest, cheapest model) because
# executive summary generation is a straightforward writing task. We already have
# all the structured data. We just need prose synthesis, not deep reasoning.
# Using Haiku here instead of Opus saves cost without sacrificing quality.
REPORTING_SYSTEM_PROMPT = """You are a cybersecurity incident report writer.

Given all findings from a SOC investigation, write a clear executive summary that:
1. Describes what happened in plain language for a non-technical audience
2. Conveys business impact and risk clearly
3. Summarizes the response actions being taken
4. Is concise (3-5 sentences maximum)

The technical details are captured separately. Focus on clarity and business relevance."""


# === Main Entry Point ===

async def run_reporting(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]
    threat_intel = state["threat_intel"]
    investigation = state.get("investigation")
    remediation = state["remediation"]

    logger.info(f"[Reporting] Compiling incident report for alert {alert_id}")

    # === Confidence Calibration ===
    # Confidence calibration: combine triage confidence (how sure the model is about
    # severity) and normalized risk score (how dangerous the threat intel says it is)
    # into a single pipeline-level confidence number. The 0.6/0.4 weighting reflects
    # that triage classification accuracy matters slightly more than risk scoring.
    # This composite score is tracked over time in calibration.py to measure whether
    # the pipeline's stated confidence matches its actual accuracy.
    triage_conf = triage.confidence
    risk_normalized = threat_intel.risk_score / 10.0
    overall_confidence = round((triage_conf * 0.6) + (risk_normalized * 0.4), 3)

    # Feed all structured findings to the LLM. Haiku is fast enough that this single
    # call does not add meaningful latency to the end of the pipeline.
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
                # Prompt caching still benefits Haiku even though it is cheap:
                # caching reduces latency which matters for the final pipeline step.
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

    # === Agent Memory Write-Back ===
    # After the pipeline completes, store what we learned about each entity involved.
    # The next alert that mentions the same IP or hostname will find this entry in
    # recall_memories() and get historical context before analysis begins.
    # This is what makes the platform learn across incidents rather than starting cold
    # every time the same attacker infrastructure reappears.
    entities_to_remember = []
    if alert.source_ip:
        entities_to_remember.append(("ip", alert.source_ip))
    if alert.destination_ip:
        entities_to_remember.append(("ip", alert.destination_ip))
    if alert.affected_host:
        entities_to_remember.append(("host", alert.affected_host))

    # Keep the stored summary compact so it fits comfortably in future prompts
    # alongside other memory entries without overwhelming the context window.
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
