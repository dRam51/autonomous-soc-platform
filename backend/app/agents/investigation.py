"""
Investigation Agent — Deep dive for medium/high/critical alerts.
Reconstructs attack timeline, identifies lateral movement, and assesses blast radius.
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import InvestigationResult
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

INVESTIGATION_SYSTEM_PROMPT = """You are a senior incident responder conducting a deep-dive investigation.

Your job is to:
1. Reconstruct the attack timeline based on all available data
2. Identify the full attack chain (initial access → execution → persistence → exfiltration etc.)
3. Determine affected assets and blast radius
4. Assess lateral movement and data exfiltration risk
5. Provide a comprehensive analysis

Think step-by-step. Be thorough but structured."""

INVESTIGATION_TOOLS = [
    {
        "name": "submit_investigation",
        "description": "Submit the investigation findings",
        "input_schema": {
            "type": "object",
            "properties": {
                "timeline": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "timestamp": {"type": "string"},
                            "event": {"type": "string"},
                        },
                    },
                    "description": "Reconstructed attack timeline events",
                },
                "attack_chain": {
                    "type": "string",
                    "description": "Step-by-step attack chain description",
                },
                "affected_assets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of affected or potentially affected assets",
                },
                "lateral_movement_detected": {
                    "type": "boolean",
                    "description": "Whether lateral movement was detected or is suspected",
                },
                "data_exfiltration_risk": {
                    "type": "boolean",
                    "description": "Whether data exfiltration is a risk",
                },
                "full_analysis": {
                    "type": "string",
                    "description": "Full investigation narrative",
                },
            },
            "required": ["attack_chain", "affected_assets", "lateral_movement_detected",
                         "data_exfiltration_risk", "full_analysis"],
        },
    }
]


async def run_investigation(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]
    threat_intel = state["threat_intel"]

    logger.info(f"[Investigation] Deep-diving alert {alert_id}")

    prompt = f"""Conduct a deep-dive investigation of this security incident.

=== Alert ===
Title: {alert.title}
Description: {alert.description}
Source IP: {alert.source_ip or 'Unknown'}
Destination IP: {alert.destination_ip or 'Unknown'}
Affected Host: {alert.affected_host or 'Unknown'}
Raw Log: {alert.raw_log or 'Not provided'}

=== Triage Results ===
Severity: {triage.severity}
MITRE Techniques: {', '.join(triage.mitre_techniques)}
Reasoning: {triage.reasoning}

=== Threat Intelligence ===
Related CVEs: {', '.join(threat_intel.related_cves)}
MITRE Tactics: {', '.join(threat_intel.mitre_tactics)}
Threat Actors: {', '.join(threat_intel.threat_actors)}
Risk Score: {threat_intel.risk_score}/10
IOC Analysis: {threat_intel.ioc_analysis}

Conduct a thorough investigation and submit your findings."""

    response = await client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2048,
        system=INVESTIGATION_SYSTEM_PROMPT,
        tools=INVESTIGATION_TOOLS,
        tool_choice={"type": "any"},
        messages=[{"role": "user", "content": prompt}],
    )

    tool_use = next(b for b in response.content if b.type == "tool_use")
    result_data = tool_use.input

    investigation_result = InvestigationResult(
        alert_id=alert_id,
        timeline=result_data.get("timeline", []),
        attack_chain=result_data["attack_chain"],
        affected_assets=result_data["affected_assets"],
        lateral_movement_detected=result_data["lateral_movement_detected"],
        data_exfiltration_risk=result_data["data_exfiltration_risk"],
        full_analysis=result_data["full_analysis"],
    )

    logger.info(f"[Investigation] Alert {alert_id} → lateral_movement={investigation_result.lateral_movement_detected}")
    return {**state, "investigation": investigation_result}
