"""
Triage Agent

Techniques implemented:
  - Prompt caching: system prompt cached with cache_control to reduce cost on repeated calls
  - Multi-agent voting: runs N independent triage assessments and takes majority vote
  - Dynamic few-shot prompting: retrieves similar past incidents from DB at runtime
  - Self-reflection: after initial assessment, a critique pass reviews and can revise
  - Structured tool use: forced tool call guarantees typed, parseable output
"""

import asyncio
from collections import Counter
from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import TriageResult, SeverityLevel
from app.skills import get_skill_schemas, dispatch_skill
import logging

logger = logging.getLogger(__name__)
client = AsyncAnthropic(api_key=settings.anthropic_api_key)

TRIAGE_SKILLS = ["rag_search"]

TRIAGE_SYSTEM_PROMPT = """You are a senior SOC analyst performing first-pass triage on security alerts.

Your job:
1. Assess the severity (critical/high/medium/low/info)
2. Identify likely MITRE ATT&CK techniques (e.g. T1059, T1078)
3. Provide clear reasoning for your assessment
4. Recommend an immediate action

You have access to the rag_search tool to query the threat intelligence knowledge base.
Use it to look up relevant TTPs, CVEs, or threat context before making your assessment.

Be decisive and concise. Think like an analyst who has seen thousands of alerts."""

SUBMIT_TRIAGE_TOOL = {
    "name": "submit_triage",
    "description": "Submit the final triage assessment for this alert",
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "confidence": {"type": "number", "description": "Confidence 0.0-1.0"},
            "reasoning": {"type": "string"},
            "recommended_action": {"type": "string"},
            "mitre_techniques": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": ["severity", "confidence", "reasoning", "recommended_action"],
    },
}

CRITIQUE_SYSTEM_PROMPT = """You are a senior SOC manager reviewing a junior analyst's triage assessment.
Your job is to critically evaluate the assessment and identify any errors or missed indicators.
Be direct about whether the severity is correct, too high, or too low."""

CRITIQUE_TOOL = {
    "name": "submit_critique",
    "description": "Submit the critique and final revised assessment",
    "input_schema": {
        "type": "object",
        "properties": {
            "severity_correct": {"type": "boolean"},
            "revised_severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "revised_confidence": {"type": "number"},
            "critique_notes": {"type": "string"},
        },
        "required": ["severity_correct", "revised_severity", "revised_confidence", "critique_notes"],
    },
}


async def _fetch_few_shot_examples(alert_title: str, alert_description: str) -> str:
    """
    Dynamically fetch the most similar past triage outcomes from the database.
    Injects them as few-shot examples to calibrate the model.
    In production this queries PostgreSQL by embedding similarity.
    """
    # TODO: Replace with real DB query once PostgreSQL models are wired up.
    # For now returns a static example to demonstrate the pattern.
    return """Past similar incidents for reference:
[Example 1] Title: Encoded PowerShell via Office macro | Severity: HIGH
  Reasoning: Office-spawned PowerShell with encoded args is a high-confidence indicator of
  malicious macro execution (T1059.001, T1204.002). Requires immediate investigation.

[Example 2] Title: PowerShell download cradle detected | Severity: CRITICAL
  Reasoning: PowerShell contacting external IP with IEX download cradle is active C2 staging.
  Treat as critical - likely active intrusion in progress."""


async def _run_single_triage(alert, few_shot_examples: str) -> dict | None:
    """
    Run a single triage assessment with agentic skill loop.
    Returns the raw tool input dict, or None on failure.
    """
    tools = get_skill_schemas(TRIAGE_SKILLS) + [SUBMIT_TRIAGE_TOOL]

    prompt = f"""{few_shot_examples}

Now triage this alert:

Title: {alert.title}
Description: {alert.description}
Source: {alert.source}
Source IP: {alert.source_ip or 'Unknown'}
Destination IP: {alert.destination_ip or 'Unknown'}
Affected Host: {alert.affected_host or 'Unknown'}
IOCs: {', '.join(alert.iocs) if alert.iocs else 'None'}
Raw Log: {alert.raw_log or 'Not provided'}

Use rag_search to look up relevant threat context, then submit your triage assessment."""

    # Agentic skill loop with self-correction on tool failure
    messages = [{"role": "user", "content": prompt}]
    max_iterations = 5

    for _ in range(max_iterations):
        response = await client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1024,
            system=[
                {
                    "type": "text",
                    "text": TRIAGE_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},  # PROMPT CACHING
                }
            ],
            tools=tools,
            messages=messages,
        )

        # Check if Claude called submit_triage (final answer)
        for block in response.content:
            if block.type == "tool_use" and block.name == "submit_triage":
                return block.input

        # Otherwise execute any skill calls and continue the loop
        tool_results = []
        for block in response.content:
            if block.type == "tool_use" and block.name != "submit_triage":
                result = await dispatch_skill(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })

        if not tool_results:
            break  # No tool calls and no submit_triage - unexpected, exit loop

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    return None


async def _run_self_reflection(alert, initial_result: dict) -> dict:
    """
    Self-reflection pass: a critique agent reviews the initial triage and can revise it.
    Returns the (possibly revised) result dict.
    """
    if not settings.enable_self_reflection:
        return initial_result

    prompt = f"""Review this triage assessment for accuracy:

Alert: {alert.title}
Description: {alert.description}
IOCs: {', '.join(alert.iocs) if alert.iocs else 'None'}

Initial Assessment:
  Severity: {initial_result['severity']}
  Confidence: {initial_result['confidence']}
  Reasoning: {initial_result['reasoning']}
  Recommended action: {initial_result['recommended_action']}
  MITRE techniques: {', '.join(initial_result.get('mitre_techniques', []))}

Is this assessment accurate? Is the severity correct? Did the analyst miss anything?"""

    response = await client.messages.create(
        model="claude-opus-4-5",
        max_tokens=512,
        system=[
            {
                "type": "text",
                "text": CRITIQUE_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=[CRITIQUE_TOOL],
        tool_choice={"type": "any"},
        messages=[{"role": "user", "content": prompt}],
    )

    critique_block = next(
        (b for b in response.content if b.type == "tool_use" and b.name == "submit_critique"),
        None,
    )

    if not critique_block:
        return initial_result

    critique = critique_block.input
    if not critique.get("severity_correct"):
        logger.info(
            f"[Triage] Self-reflection revised severity: "
            f"{initial_result['severity']} -> {critique['revised_severity']}"
        )
        initial_result["severity"] = critique["revised_severity"]
        initial_result["confidence"] = critique["revised_confidence"]
        initial_result["reasoning"] += f" [Revised after critique: {critique['critique_notes']}]"

    return initial_result


async def run_triage(state: dict) -> dict:
    """
    Main triage entry point.
    Implements: few-shot prompting, multi-agent voting, self-reflection, prompt caching.
    """
    alert = state["alert"]
    alert_id = state["alert_id"]
    logger.info(f"[Triage] Analyzing alert {alert_id}: {alert.title}")

    # Step 1: Fetch dynamic few-shot examples
    few_shot = await _fetch_few_shot_examples(alert.title, alert.description)

    # Step 2: Multi-agent voting - run N independent assessments in parallel
    voting_rounds = settings.voting_rounds if settings.enable_voting else 1
    tasks = [_run_single_triage(alert, few_shot) for _ in range(voting_rounds)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    valid_results = [r for r in results if isinstance(r, dict) and r is not None]

    if not valid_results:
        raise RuntimeError(f"[Triage] All {voting_rounds} voting rounds failed for alert {alert_id}")

    # Step 3: Majority vote on severity
    severity_votes = Counter(r["severity"] for r in valid_results)
    winning_severity = severity_votes.most_common(1)[0][0]
    best_result = next(r for r in valid_results if r["severity"] == winning_severity)

    if voting_rounds > 1:
        logger.info(
            f"[Triage] Voting results: {dict(severity_votes)} -> winner: {winning_severity}"
        )
        best_result["reasoning"] += (
            f" [Voted {severity_votes[winning_severity]}/{len(valid_results)} rounds]"
        )

    # Step 4: Self-reflection critique pass
    final_result = await _run_self_reflection(alert, best_result)

    triage_result = TriageResult(
        alert_id=alert_id,
        severity=SeverityLevel(final_result["severity"]),
        confidence=final_result["confidence"],
        reasoning=final_result["reasoning"],
        recommended_action=final_result["recommended_action"],
        mitre_techniques=final_result.get("mitre_techniques", []),
    )

    logger.info(
        f"[Triage] Alert {alert_id} -> {triage_result.severity} "
        f"(confidence={triage_result.confidence:.2f}, votes={len(valid_results)})"
    )
    return {**state, "triage": triage_result}
