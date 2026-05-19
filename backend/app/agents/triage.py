"""
Triage Agent — First responder.
Normalizes raw alert data, scores severity, and identifies MITRE ATT&CK techniques.
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import TriageResult, SeverityLevel
import json
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

TRIAGE_SYSTEM_PROMPT = """You are a senior SOC analyst performing first-pass triage on security alerts.

Your job:
1. Assess the severity (critical/high/medium/low/info)
2. Identify likely MITRE ATT&CK techniques (e.g. T1059, T1078)
3. Provide clear reasoning for your assessment
4. Recommend an immediate action

Be decisive and concise. Think like an analyst who has seen thousands of alerts."""

TRIAGE_TOOLS = [
    {
        "name": "submit_triage",
        "description": "Submit the triage assessment for this alert",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Assessed severity level",
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence score 0.0-1.0",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Analyst reasoning for the severity assessment",
                },
                "recommended_action": {
                    "type": "string",
                    "description": "Immediate recommended action",
                },
                "mitre_techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of likely MITRE ATT&CK technique IDs",
                },
            },
            "required": ["severity", "confidence", "reasoning", "recommended_action"],
        },
    }
]


async def run_triage(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]

    logger.info(f"[Triage] Analyzing alert {alert_id}: {alert.title}")

    prompt = f"""Triage this security alert:

Title: {alert.title}
Description: {alert.description}
Source: {alert.source}
Source IP: {alert.source_ip or 'Unknown'}
Destination IP: {alert.destination_ip or 'Unknown'}
Affected Host: {alert.affected_host or 'Unknown'}
IOCs: {', '.join(alert.iocs) if alert.iocs else 'None'}
Raw Log: {alert.raw_log or 'Not provided'}

Perform triage and submit your assessment using the submit_triage tool."""

    response = await client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        system=TRIAGE_SYSTEM_PROMPT,
        tools=TRIAGE_TOOLS,
        tool_choice={"type": "any"},
        messages=[{"role": "user", "content": prompt}],
    )

    tool_use = next(b for b in response.content if b.type == "tool_use")
    result_data = tool_use.input

    triage_result = TriageResult(
        alert_id=alert_id,
        severity=SeverityLevel(result_data["severity"]),
        confidence=result_data["confidence"],
        reasoning=result_data["reasoning"],
        recommended_action=result_data["recommended_action"],
        mitre_techniques=result_data.get("mitre_techniques", []),
    )

    logger.info(f"[Triage] Alert {alert_id} → {triage_result.severity} (confidence: {triage_result.confidence:.2f})")
    return {**state, "triage": triage_result}
