"""
Investigation Agent

Techniques implemented:
  - Extended thinking: Claude reasons step-by-step before producing output
  - Agentic self-correction: retries with alternate approaches on skill failure
  - Skills integration: shodan, geolocate_ip, virustotal, rag_search
  - Prompt caching: system prompt cached
  - Agent memory: prior incident context injected from memory store
"""

from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import InvestigationResult
from app.skills import get_skill_schemas, dispatch_skill
from app.core.memory import recall_memories, extract_entities_from_alert
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

# Investigation needs the deepest skill set: host intelligence (Shodan), IP context,
# IOC reputation (VirusTotal), and knowledge base search for attack pattern context.
INVESTIGATION_SKILLS = ["get_host_info", "geolocate_ip", "lookup_virustotal", "rag_search"]

# === System Prompt ===

# Prompt caching: the system prompt here is extensive and stable. Caching it means
# the first investigation call pays the tokenization cost; all subsequent calls
# with the same prompt bytes reuse the cached KV state at lower cost and latency.
INVESTIGATION_SYSTEM_PROMPT = """You are a senior incident responder conducting a deep-dive investigation.

You have access to:
  - get_host_info: Shodan lookup for open ports, services, C2 tags
  - geolocate_ip: Country, ASN, proxy/VPN/datacenter flags
  - lookup_virustotal: IOC reputation and detection ratio
  - rag_search: MITRE ATT&CK and threat intel knowledge base

Investigation approach:
1. Investigate all IPs and domains using available tools
2. Search for attack pattern context in the knowledge base
3. Reconstruct the attack timeline step by step
4. Identify the full attack chain from initial access to current stage
5. Determine blast radius: affected assets, lateral movement, exfiltration risk
6. Write a comprehensive investigation narrative

Think step by step. Be thorough. If a tool returns no data, try a different approach."""

# The submit_investigation tool enforces structure on what would otherwise be a
# multi-page prose investigation narrative. Downstream agents (remediation, reporting)
# need machine-readable fields, not a free-form write-up.
SUBMIT_INVESTIGATION_TOOL = {
    "name": "submit_investigation",
    "description": "Submit the completed investigation findings",
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
            },
            "attack_chain": {"type": "string"},
            "affected_assets": {"type": "array", "items": {"type": "string"}},
            "lateral_movement_detected": {"type": "boolean"},
            "data_exfiltration_risk": {"type": "boolean"},
            "full_analysis": {"type": "string"},
        },
        "required": [
            "attack_chain", "affected_assets", "lateral_movement_detected",
            "data_exfiltration_risk", "full_analysis",
        ],
    },
}


# === Main Entry Point ===

async def run_investigation(state: dict) -> dict:
    """
    Investigation agent with extended thinking, self-correcting skill loop,
    and memory-augmented context.

    This is the most expensive and most thorough agent in the pipeline. It runs
    only for medium+ severity alerts (controlled by supervisor routing) and has
    the longest iteration budget because reconstruction of an attack chain requires
    exploring multiple data sources before conclusions can be drawn.
    """
    alert = state["alert"]
    alert_id = state["alert_id"]
    triage = state["triage"]
    threat_intel = state["threat_intel"]

    logger.info(f"[Investigation] Deep-diving alert {alert_id}")

    # === Agent Memory ===
    # Before analyzing this alert, retrieve what we know about the entities involved
    # from prior incidents. If 203.0.113.42 was a C2 server in a campaign last week,
    # that context should inform this investigation even though it arrived in a
    # different alert. This is the "cross-session memory" pattern.
    entities = await extract_entities_from_alert(alert)
    memory_context = await recall_memories(entities)

    tools = get_skill_schemas(INVESTIGATION_SKILLS) + [SUBMIT_INVESTIGATION_TOOL]

    # The prompt bundles all prior agent outputs so the investigator has full context.
    # This is a key design principle: each agent in the pipeline inherits the work
    # of all prior agents rather than starting from scratch.
    prompt = f"""Conduct a deep-dive investigation of this security incident.

=== Alert ===
Title: {alert.title}
Description: {alert.description}
Source IP: {alert.source_ip or 'Unknown'}
Destination IP: {alert.destination_ip or 'Unknown'}
Affected Host: {alert.affected_host or 'Unknown'}
IOCs: {', '.join(alert.iocs) if alert.iocs else 'None'}
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

=== Agent Memory (Prior Incidents) ===
{memory_context}

Use the available tools to investigate all IPs, look up host intelligence, and search
for attack pattern context. Then submit your complete investigation findings."""

    messages = [{"role": "user", "content": prompt}]
    # Longer iteration budget than threat_intel: building a timeline may require
    # looking up every IP, then cross-referencing each in the knowledge base.
    max_iterations = 10

    # === Extended Thinking ===
    # Extended thinking gives the model a private "scratchpad" of reasoning tokens
    # before it produces its response. For complex attack chain reconstruction,
    # this matters because the model needs to correlate multiple tool results,
    # consider alternative hypotheses, and build a coherent timeline. Without
    # extended thinking it might jump to the first plausible conclusion.
    # budget_tokens caps the scratchpad size to control cost and latency.
    thinking_params = {}
    if settings.enable_extended_thinking:
        thinking_params = {
            "thinking": {
                "type": "enabled",
                "budget_tokens": 8000,  # Allow up to 8k tokens of internal reasoning
            }
        }

    for iteration in range(max_iterations):
        response = await client.messages.create(
            model="claude-opus-4-5",
            max_tokens=4096,
            system=[
                {
                    "type": "text",
                    "text": INVESTIGATION_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=tools,
            messages=messages,
            # Spread thinking_params in: if empty dict, no thinking params are sent.
            **thinking_params,
        )

        # Check for the final submission first before processing any tool calls.
        for block in response.content:
            if block.type == "tool_use" and block.name == "submit_investigation":
                data = block.input
                result = InvestigationResult(
                    alert_id=alert_id,
                    timeline=data.get("timeline", []),
                    attack_chain=data["attack_chain"],
                    affected_assets=data["affected_assets"],
                    lateral_movement_detected=data["lateral_movement_detected"],
                    data_exfiltration_risk=data["data_exfiltration_risk"],
                    full_analysis=data["full_analysis"],
                )
                logger.info(
                    f"[Investigation] Alert {alert_id} -> "
                    f"lateral_movement={result.lateral_movement_detected} "
                    f"exfil_risk={result.data_exfiltration_risk}"
                )
                return {**state, "investigation": result}

        # === Agentic Self-Correction ===
        # Execute skill calls and inject results. If a skill returns an error, we
        # append a system note telling the model to try a different approach. This
        # prevents the model from getting stuck in a loop retrying a tool that is
        # down. It can adapt: "Shodan is unavailable, use rag_search instead."
        tool_results = []
        for block in response.content:
            if block.type == "tool_use" and block.name != "submit_investigation":
                result_text = await dispatch_skill(block.name, block.input)

                # Self-correction hint: if the skill failed, steer the model away from
                # retrying and toward an alternative data source.
                if "failed" in result_text.lower() or "not configured" in result_text.lower():
                    result_text += (
                        "\n[System note: This tool is unavailable. "
                        "Try a different approach or tool to gather this information.]"
                    )

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })

        if not tool_results:
            break

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    raise RuntimeError(f"[Investigation] Agent did not submit findings for alert {alert_id}")
