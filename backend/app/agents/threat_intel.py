"""
Threat Intel Agent

Techniques implemented:
  - Prompt caching: system prompt cached to reduce cost
  - Skills integration: calls virustotal, cisa_kev, nvd, rag_search dynamically
  - Agentic skill loop: Claude decides which skills to call based on the alert context
  - Structured tool use: submit_threat_intel guarantees typed output
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import ThreatIntelResult
from app.skills import get_skill_schemas, dispatch_skill
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

# All four skills are available to this agent. The model autonomously decides
# which ones to call based on what the alert actually contains (IOCs, CVEs, etc.).
# Giving the model the full toolkit and letting it self-select is more flexible
# than hard-coding "always check VirusTotal for every IP."
THREAT_INTEL_SKILLS = ["lookup_virustotal", "check_cisa_kev", "get_cve_details", "rag_search"]

# === System Prompt ===

# Prompt caching: this system prompt is large and used on every alert. Marking it
# with cache_control means the server tokenizes it once and reuses the KV cache
# for subsequent calls that carry the same prompt bytes, reducing latency and cost.
THREAT_INTEL_SYSTEM_PROMPT = """You are a cyber threat intelligence analyst.

Given a security alert and triage findings, enrich the alert with threat intelligence.
You have access to these tools:
  - lookup_virustotal: check IPs, domains, hashes against VirusTotal
  - check_cisa_kev: verify if a CVE is actively exploited per CISA
  - get_cve_details: fetch CVE details from NIST NVD
  - rag_search: search the MITRE ATT&CK and threat intel knowledge base

Use the tools proactively. For each IOC, check VirusTotal. For each CVE, check CISA KEV.
For MITRE techniques from triage, search the knowledge base for context.

Then submit your enrichment with:
  - Related CVEs and exploitation status
  - MITRE ATT&CK tactics
  - Known threat actors
  - IOC analysis summary
  - Overall risk score (0.0-10.0)"""

# Forcing a submit_threat_intel call ensures downstream agents always receive a
# ThreatIntelResult-compatible dict rather than unstructured prose. Without it, the
# model might just narrate its findings and the pipeline would have nothing to parse.
SUBMIT_THREAT_INTEL_TOOL = {
    "name": "submit_threat_intel",
    "description": "Submit the completed threat intelligence enrichment",
    "input_schema": {
        "type": "object",
        "properties": {
            "related_cves": {"type": "array", "items": {"type": "string"}},
            "mitre_tactics": {"type": "array", "items": {"type": "string"}},
            "threat_actors": {"type": "array", "items": {"type": "string"}},
            "ioc_analysis": {"type": "string"},
            "risk_score": {"type": "number", "description": "0.0-10.0"},
        },
        "required": ["ioc_analysis", "risk_score"],
    },
}


# === Main Entry Point ===

async def run_threat_intel(state: dict) -> dict:
    """
    Threat Intel agent with full agentic skill loop.
    Claude autonomously decides which tools to call based on alert context.

    This is the core agentic tool use pattern: the model receives tools as a menu
    and iterates until it has gathered enough intelligence to produce a final answer.
    Each tool result is injected back into the conversation so the model can use
    prior results to decide what to look up next (e.g., find a CVE then check KEV).
    """
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]

    logger.info(f"[ThreatIntel] Enriching alert {alert_id}")

    tools = get_skill_schemas(THREAT_INTEL_SKILLS) + [SUBMIT_THREAT_INTEL_TOOL]

    # Include triage findings in the prompt so the model knows what MITRE techniques
    # were already identified and can look them up in the knowledge base without
    # rediscovering them from scratch.
    prompt = f"""Enrich this security alert with threat intelligence.

Alert: {alert.title}
Description: {alert.description}
Source IP: {alert.source_ip or 'Unknown'}
Destination IP: {alert.destination_ip or 'Unknown'}
IOCs: {', '.join(alert.iocs) if alert.iocs else 'None'}

Triage findings:
  Severity: {triage.severity}
  MITRE Techniques: {', '.join(triage.mitre_techniques) if triage.mitre_techniques else 'None identified'}
  Reasoning: {triage.reasoning}

Use the available tools to enrich this alert, then submit your threat intelligence findings."""

    messages = [{"role": "user", "content": prompt}]
    # More iterations than triage because comprehensive enrichment may require many
    # tool calls: one VT lookup per IOC, one KEV check per CVE, one rag_search per TTP.
    max_iterations = 8

    for _ in range(max_iterations):
        response = await client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1536,
            system=[
                {
                    "type": "text",
                    "text": THREAT_INTEL_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},  # PROMPT CACHING
                }
            ],
            tools=tools,
            messages=messages,
        )

        # If the model called submit_threat_intel, parse and return the result.
        for block in response.content:
            if block.type == "tool_use" and block.name == "submit_threat_intel":
                data = block.input
                result = ThreatIntelResult(
                    alert_id=alert_id,
                    related_cves=data.get("related_cves", []),
                    mitre_tactics=data.get("mitre_tactics", []),
                    threat_actors=data.get("threat_actors", []),
                    ioc_analysis=data["ioc_analysis"],
                    risk_score=data["risk_score"],
                )
                logger.info(
                    f"[ThreatIntel] Alert {alert_id} -> risk_score={result.risk_score}/10 "
                    f"cves={result.related_cves} actors={result.threat_actors}"
                )
                return {**state, "threat_intel": result}

        # Self-correction: execute skill calls and inject results back.
        # If a skill fails (API down, key missing), the error string goes into context
        # so the model knows to try a different approach or skip that enrichment step.
        tool_results = []
        for block in response.content:
            if block.type == "tool_use" and block.name != "submit_threat_intel":
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

    raise RuntimeError(f"[ThreatIntel] Agent did not submit findings for alert {alert_id}")
