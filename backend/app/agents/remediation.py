"""
Remediation Agent

Techniques implemented:
  - Prompt caching: system prompt cached
  - Skills integration: nvd and cisa_kev for live patch and exploitation data
  - Structured tool use: forced submit_remediation call
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import RemediationResult
from app.skills import get_skill_schemas, dispatch_skill
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

REMEDIATION_SKILLS = ["get_cve_details", "check_cisa_kev"]

REMEDIATION_SYSTEM_PROMPT = """You are a cybersecurity remediation specialist.

You have access to:
  - get_cve_details: fetch CVSS scores, affected products, and patch info from NVD
  - check_cisa_kev: verify if CVEs are actively exploited and get required actions

Use these tools to look up patch availability and exploitation status for any CVEs
identified in the incident before generating your remediation plan.

Generate a structured remediation plan with:
1. Immediate actions (containment - do these NOW)
2. Short-term actions (eradication and recovery - within 24-72 hours)
3. Long-term recommendations (hardening - within weeks/months)

Be specific, actionable, and prioritized based on actual exploitation data."""

SUBMIT_REMEDIATION_TOOL = {
    "name": "submit_remediation",
    "description": "Submit the completed remediation plan",
    "input_schema": {
        "type": "object",
        "properties": {
            "immediate_actions": {"type": "array", "items": {"type": "string"}},
            "short_term_actions": {"type": "array", "items": {"type": "string"}},
            "long_term_recommendations": {"type": "array", "items": {"type": "string"}},
            "playbook_reference": {"type": "string"},
            "estimated_effort": {"type": "string"},
        },
        "required": ["immediate_actions", "short_term_actions", "long_term_recommendations", "estimated_effort"],
    },
}


async def run_remediation(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]
    threat_intel = state["threat_intel"]
    investigation = state.get("investigation")

    logger.info(f"[Remediation] Generating playbook for alert {alert_id}")

    tools = get_skill_schemas(REMEDIATION_SKILLS) + [SUBMIT_REMEDIATION_TOOL]

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

Use get_cve_details and check_cisa_kev to look up patch availability and exploitation
status for the CVEs above, then submit a prioritized remediation plan."""

    messages = [{"role": "user", "content": prompt}]
    max_iterations = 6

    for _ in range(max_iterations):
        response = await client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1536,
            system=[
                {
                    "type": "text",
                    "text": REMEDIATION_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=tools,
            messages=messages,
        )

        for block in response.content:
            if block.type == "tool_use" and block.name == "submit_remediation":
                data = block.input
                result = RemediationResult(
                    alert_id=alert_id,
                    immediate_actions=data["immediate_actions"],
                    short_term_actions=data["short_term_actions"],
                    long_term_recommendations=data["long_term_recommendations"],
                    playbook_reference=data.get("playbook_reference"),
                    estimated_effort=data["estimated_effort"],
                )
                logger.info(
                    f"[Remediation] Alert {alert_id} -> "
                    f"{len(result.immediate_actions)} immediate actions"
                )
                return {**state, "remediation": result}

        tool_results = []
        for block in response.content:
            if block.type == "tool_use" and block.name != "submit_remediation":
                result_text = await dispatch_skill(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })

        if not tool_results:
            break

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    raise RuntimeError(f"[Remediation] Agent did not submit plan for alert {alert_id}")
