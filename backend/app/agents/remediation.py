"""
Remediation Agent — Generates prioritized remediation playbooks.
Produces immediate actions, short-term fixes, and long-term hardening recommendations.
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import RemediationResult
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

REMEDIATION_SYSTEM_PROMPT = """You are a cybersecurity remediation specialist.

Given an incident's full context, generate a structured remediation plan with:
1. Immediate actions (containment — do these NOW)
2. Short-term actions (eradication & recovery — within 24-72 hours)
3. Long-term recommendations (hardening — within weeks/months)

Be specific, actionable, and prioritized. Tailor recommendations to the actual attack techniques used."""

REMEDIATION_TOOLS = [
    {
        "name": "submit_remediation",
        "description": "Submit the remediation plan",
        "input_schema": {
            "type": "object",
            "properties": {
                "immediate_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Immediate containment actions to take right now",
                },
                "short_term_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Eradication and recovery steps within 24-72 hours",
                },
                "long_term_recommendations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Strategic hardening recommendations",
                },
                "playbook_reference": {
                    "type": "string",
                    "description": "Reference to a standard playbook if applicable (e.g. NIST IR, SANS)",
                },
                "estimated_effort": {
                    "type": "string",
                    "description": "Estimated total effort for full remediation (e.g. '4-8 hours', '2-3 days')",
                },
            },
            "required": ["immediate_actions", "short_term_actions", "long_term_recommendations", "estimated_effort"],
        },
    }
]


async def run_remediation(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]
    threat_intel = state["threat_intel"]
    investigation = state.get("investigation")

    logger.info(f"[Remediation] Generating playbook for alert {alert_id}")

    investigation_context = ""
    if investigation:
        investigation_context = f"""
=== Investigation Findings ===
Attack Chain: {investigation.attack_chain}
Affected Assets: {', '.join(investigation.affected_assets)}
Lateral Movement: {investigation.lateral_movement_detected}
Exfiltration Risk: {investigation.data_exfiltration_risk}
"""

    prompt = f"""Generate a remediation plan for this security incident.

=== Incident Summary ===
Title: {alert.title}
Severity: {triage.severity}
MITRE Techniques: {', '.join(triage.mitre_techniques)}
MITRE Tactics: {', '.join(threat_intel.mitre_tactics)}
Related CVEs: {', '.join(threat_intel.related_cves)}
Risk Score: {threat_intel.risk_score}/10
{investigation_context}

Submit a prioritized remediation plan using the submit_remediation tool."""

    response = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1536,
        system=REMEDIATION_SYSTEM_PROMPT,
        tools=REMEDIATION_TOOLS,
        tool_choice={"type": "any"},
        messages=[{"role": "user", "content": prompt}],
    )

    tool_use = next(b for b in response.content if b.type == "tool_use")
    result_data = tool_use.input

    remediation_result = RemediationResult(
        alert_id=alert_id,
        immediate_actions=result_data["immediate_actions"],
        short_term_actions=result_data["short_term_actions"],
        long_term_recommendations=result_data["long_term_recommendations"],
        playbook_reference=result_data.get("playbook_reference"),
        estimated_effort=result_data["estimated_effort"],
    )

    logger.info(f"[Remediation] Alert {alert_id} → {len(remediation_result.immediate_actions)} immediate actions")
    return {**state, "remediation": remediation_result}
