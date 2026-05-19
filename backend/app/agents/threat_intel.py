"""
Threat Intel Agent — RAG-powered enrichment.
Queries MITRE ATT&CK, CVE/NVD, and CISA KEV corpus to enrich the alert.
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import ThreatIntelResult
from app.core.vector_store import query_threat_intel
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

THREAT_INTEL_SYSTEM_PROMPT = """You are a cyber threat intelligence analyst.
Given a security alert and relevant threat intelligence context retrieved from our knowledge base,
enrich the alert with:
- Related CVEs and their CVSS scores
- MITRE ATT&CK tactics and techniques
- Known threat actors that use these TTPs
- IOC analysis
- An overall risk score (0.0-10.0)

Base your analysis strictly on the provided context. If information is not available, say so."""

THREAT_INTEL_TOOLS = [
    {
        "name": "submit_threat_intel",
        "description": "Submit the threat intelligence enrichment",
        "input_schema": {
            "type": "object",
            "properties": {
                "related_cves": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of related CVE IDs",
                },
                "mitre_tactics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "MITRE ATT&CK tactic names",
                },
                "threat_actors": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Known threat actor groups",
                },
                "ioc_analysis": {
                    "type": "string",
                    "description": "Analysis of the indicators of compromise",
                },
                "risk_score": {
                    "type": "number",
                    "description": "Overall risk score 0.0-10.0",
                },
            },
            "required": ["ioc_analysis", "risk_score"],
        },
    }
]


async def run_threat_intel(state: dict) -> dict:
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]

    logger.info(f"[ThreatIntel] Enriching alert {alert_id}")

    # RAG: retrieve relevant threat intel from vector store
    query = f"{alert.title} {alert.description} {' '.join(triage.mitre_techniques)}"
    rag_context = await query_threat_intel(query, top_k=5)

    prompt = f"""Enrich this security alert with threat intelligence.

Alert: {alert.title}
Description: {alert.description}
IOCs: {', '.join(alert.iocs) if alert.iocs else 'None'}
MITRE Techniques (from triage): {', '.join(triage.mitre_techniques)}

Retrieved Threat Intelligence Context:
{rag_context}

Submit your enrichment using the submit_threat_intel tool."""

    response = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        system=THREAT_INTEL_SYSTEM_PROMPT,
        tools=THREAT_INTEL_TOOLS,
        tool_choice={"type": "any"},
        messages=[{"role": "user", "content": prompt}],
    )

    tool_use = next(b for b in response.content if b.type == "tool_use")
    result_data = tool_use.input

    threat_intel_result = ThreatIntelResult(
        alert_id=alert_id,
        related_cves=result_data.get("related_cves", []),
        mitre_tactics=result_data.get("mitre_tactics", []),
        threat_actors=result_data.get("threat_actors", []),
        ioc_analysis=result_data["ioc_analysis"],
        risk_score=result_data["risk_score"],
    )

    logger.info(f"[ThreatIntel] Alert {alert_id} → risk score: {threat_intel_result.risk_score}/10")
    return {**state, "threat_intel": threat_intel_result}
