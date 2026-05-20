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

# Only expose rag_search to the triage agent. Triage is fast-pass; we don't want
# it burning time on Shodan or VirusTotal - those belong to later agents.
TRIAGE_SKILLS = ["rag_search"]

# === System Prompts ===

# Prompt caching: the system prompt is marked with cache_control so Claude caches
# the tokenized version server-side. Every subsequent call that sends the identical
# system prompt bytes hits the cache instead of re-tokenizing it, cutting latency
# and input token cost by up to 90% on the cached portion. This matters most here
# because triage runs N times in the voting loop.
TRIAGE_SYSTEM_PROMPT = """You are a senior SOC analyst performing first-pass triage on security alerts.

Your job:
1. Assess the severity (critical/high/medium/low/info)
2. Identify likely MITRE ATT&CK techniques (e.g. T1059, T1078)
3. Provide clear reasoning for your assessment
4. Recommend an immediate action

You have access to the rag_search tool to query the threat intelligence knowledge base.
Use it to look up relevant TTPs, CVEs, or threat context before making your assessment.

Be decisive and concise. Think like an analyst who has seen thousands of alerts."""

# Structured tool use: by forcing the model to call submit_triage rather than
# responding with free-form text, we guarantee the output matches our schema.
# This is the LLM equivalent of requiring a report on a specific form template.
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

# Self-reflection uses a separate "critic" persona with a different system prompt.
# Keeping the critic prompt distinct from the analyst prompt prevents the model from
# simply agreeing with itself. It has to play the role of a skeptical manager.
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


# === Few-Shot Example Fetcher ===

async def _fetch_few_shot_examples(alert_title: str, alert_description: str) -> str:
    """
    Dynamically fetch the most similar past triage outcomes from the database.
    Injects them as few-shot examples to calibrate the model.
    In production this queries PostgreSQL by embedding similarity.

    Few-shot prompting works by showing the model examples of correct behavior
    before asking it to perform the same task. The examples anchor the model's
    output format and severity calibration to real prior decisions, not just
    training data patterns.
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


# === Single Voting Round ===

async def _run_single_triage(alert, few_shot_examples: str) -> dict | None:
    """
    Run a single triage assessment with agentic skill loop.
    Returns the raw tool input dict, or None on failure.

    The agentic loop lets the model call rag_search to look up threat context
    before committing to a severity. This is the "agentic tool use" pattern:
    the model decides when it has enough information to submit its final answer.
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

    # Agentic skill loop with self-correction on tool failure.
    # Each iteration is one round-trip to Claude. The model sees all prior
    # tool results in the messages array and decides what to do next.
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
                    # cache_control marks this block for server-side caching.
                    # The cache key is the exact bytes of this text, so identical
                    # system prompts across voting rounds all hit the same cache entry.
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=tools,
            messages=messages,
        )

        # If the model called submit_triage, we have our answer. Exit early.
        for block in response.content:
            if block.type == "tool_use" and block.name == "submit_triage":
                return block.input

        # Otherwise execute any skill calls and feed results back into the conversation.
        # This is the "observe results and continue" part of the agentic loop.
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


# === Self-Reflection Pass ===

async def _run_self_reflection(alert, initial_result: dict) -> dict:
    """
    Self-reflection pass: a critique agent reviews the initial triage and can revise it.
    Returns the (possibly revised) result dict.

    Self-reflection works by making a second API call with a critic role and the
    initial answer as input. The critic evaluates whether the severity is correct
    and can override it. This catches cases where the first analyst was too hasty
    or missed a key indicator, similar to a two-analyst review process.
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
                # Same caching pattern: if this critique is called many times across
                # different alerts, the system prompt bytes are identical and stay cached.
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=[CRITIQUE_TOOL],
        # tool_choice "any" forces the model to call a tool rather than respond in text.
        # This guarantees we get a structured critique object, not a prose paragraph.
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
    # Only mutate the result if the critic found the severity wrong. If correct, pass through.
    if not critique.get("severity_correct"):
        logger.info(
            f"[Triage] Self-reflection revised severity: "
            f"{initial_result['severity']} -> {critique['revised_severity']}"
        )
        initial_result["severity"] = critique["revised_severity"]
        initial_result["confidence"] = critique["revised_confidence"]
        # Append the critique notes so analysts can see why the revision happened.
        initial_result["reasoning"] += f" [Revised after critique: {critique['critique_notes']}]"

    return initial_result


# === Main Entry Point ===

async def run_triage(state: dict) -> dict:
    """
    Main triage entry point.
    Implements: few-shot prompting, multi-agent voting, self-reflection, prompt caching.

    The execution order matters: fetch examples first (they condition the vote),
    then run N independent votes in parallel, then apply self-reflection to the winner.
    """
    alert = state["alert"]
    alert_id = state["alert_id"]
    logger.info(f"[Triage] Analyzing alert {alert_id}: {alert.title}")

    # Step 1: Fetch dynamic few-shot examples. These are included in every voting
    # round so all N models see the same calibration examples.
    few_shot = await _fetch_few_shot_examples(alert.title, alert.description)

    # Step 2: Multi-agent voting. Run N independent assessments in parallel, then
    # pick the majority severity. This reduces single-call variance: one unlucky
    # call that hallucinates "info" severity gets outvoted by two correct "high" calls.
    # Think of it as a quorum vote before paging the on-call responder.
    voting_rounds = settings.voting_rounds if settings.enable_voting else 1
    tasks = [_run_single_triage(alert, few_shot) for _ in range(voting_rounds)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    valid_results = [r for r in results if isinstance(r, dict) and r is not None]

    if not valid_results:
        raise RuntimeError(f"[Triage] All {voting_rounds} voting rounds failed for alert {alert_id}")

    # Step 3: Majority vote on severity. Counter.most_common(1) gives the winning
    # severity. We then pick the first result that matches, so we use that call's
    # full reasoning and confidence, not just the severity string.
    severity_votes = Counter(r["severity"] for r in valid_results)
    winning_severity = severity_votes.most_common(1)[0][0]
    best_result = next(r for r in valid_results if r["severity"] == winning_severity)

    if voting_rounds > 1:
        logger.info(
            f"[Triage] Voting results: {dict(severity_votes)} -> winner: {winning_severity}"
        )
        # Append vote count to reasoning for audit trail visibility.
        best_result["reasoning"] += (
            f" [Voted {severity_votes[winning_severity]}/{len(valid_results)} rounds]"
        )

    # Step 4: Self-reflection critique pass. The winner goes to a separate model
    # call acting as a skeptical reviewer. If the reviewer disagrees, the severity
    # is revised. This is a final quality gate before the result enters the pipeline.
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
