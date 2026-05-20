"""
Batch Processing Tasks

Uses Anthropic's Batch API for non-urgent, high-volume workloads where
cost matters more than latency. Batch requests are ~50% cheaper than
real-time API calls and processed asynchronously within 24 hours.

Batch API pattern:
  The Batch API bundles N individual API requests into one submission.
  Instead of making N sequential calls (each incurring per-call overhead
  and hitting rate limits), you submit one batch and retrieve all results
  when ready. This is analogous to bulk SQL inserts vs. N individual inserts.
  The trade-off: you get results in bulk (minutes to hours) instead of
  in real-time (seconds).

Use cases:
  - Overnight threat hunt: re-analyze historical alerts with updated prompts
  - Bulk CVE enrichment: enrich a batch of CVEs with threat context
  - Retroactive severity re-scoring: re-triage old alerts after prompt improvements
  - Corpus summarization: summarize new threat reports for RAG ingestion
"""

import anthropic
import json
from datetime import datetime
from app.config import settings
from app.models.schemas import AlertCreate
import logging

logger = logging.getLogger(__name__)
client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)


# === Batch Re-Triage ===

async def batch_retriage_alerts(alerts: list[dict]) -> str:
    """
    Submit a batch of historical alerts for re-triage using the Anthropic Batch API.
    Returns a batch_id to poll for results.

    Use this when you have improved the triage prompt and want to retroactively
    re-score old alerts, or when you have imported a bulk dataset of historical
    incidents and need initial triage scores for all of them.

    The batch API is the right choice here because:
    - Re-triage is not time-sensitive (results in hours are fine)
    - Volume can be large (thousands of historical alerts)
    - Cost savings matter at scale (50% cheaper vs. real-time API)

    Args:
        alerts: list of dicts with keys: alert_id, title, description, source, iocs

    Returns:
        batch_id: string identifier to retrieve results later via get_batch_status()
    """
    requests = []
    for alert in alerts:
        prompt = (
            f"Triage this security alert and respond with JSON only:\n"
            f"Title: {alert.get('title', '')}\n"
            f"Description: {alert.get('description', '')}\n"
            f"Source: {alert.get('source', '')}\n"
            f"IOCs: {', '.join(alert.get('iocs', []))}\n\n"
            f"Respond with: {{\"severity\": \"critical|high|medium|low|info\", "
            f"\"confidence\": 0.0-1.0, \"reasoning\": \"...\"}}"
        )
        requests.append(
            anthropic.types.message_create_params.Request(
                # custom_id allows correlating batch results back to source alerts.
                # Using alert_id here means results[n].custom_id == alert_id.
                custom_id=alert.get("alert_id", f"alert_{len(requests)}"),
                params=anthropic.types.MessageCreateParamsNonStreaming(
                    # Haiku is used for batch re-triage: fast, cheap, adequate for
                    # bulk scoring where individual accuracy matters less than throughput.
                    # The voting and self-reflection that Opus provides in real-time
                    # triage are skipped here to maximize cost efficiency.
                    model="claude-haiku-4-5",
                    max_tokens=256,
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
        )

    batch = await client.messages.batches.create(requests=requests)
    logger.info(f"[Batch] Submitted {len(requests)} alerts for re-triage. Batch ID: {batch.id}")
    return batch.id


# === Batch CVE Enrichment ===

async def batch_enrich_cves(cve_ids: list[str]) -> str:
    """
    Submit a batch of CVE IDs for threat context enrichment.
    Returns a batch_id to poll for results.

    Use this to pre-enrich your knowledge base with LLM-generated summaries
    of CVE threat context, which can then be indexed into Pinecone.

    This is useful when CISA releases a new KEV batch: pull all new CVE IDs,
    submit one enrichment batch, and when results return, add the summaries
    to the vector store so RAG queries immediately benefit from the new context.
    """
    requests = []
    for cve_id in cve_ids:
        prompt = (
            f"Provide a concise threat intelligence summary for {cve_id}. "
            f"Include: attack complexity, exploitation likelihood, affected systems, "
            f"known threat actor usage, and detection recommendations. "
            f"Keep it under 200 words."
        )
        requests.append(
            anthropic.types.message_create_params.Request(
                custom_id=cve_id,
                params=anthropic.types.MessageCreateParamsNonStreaming(
                    model="claude-haiku-4-5",
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
        )

    batch = await client.messages.batches.create(requests=requests)
    logger.info(f"[Batch] Submitted {len(cve_ids)} CVEs for enrichment. Batch ID: {batch.id}")
    return batch.id


# === Status and Result Retrieval ===

async def get_batch_status(batch_id: str) -> dict:
    """Check the status of a submitted batch job.

    processing_status transitions: "in_progress" -> "ended" (or "canceling" if cancelled).
    Poll this until processing_status == "ended" before calling retrieve_batch_results().
    """
    batch = await client.messages.batches.retrieve(batch_id)
    return {
        "batch_id": batch_id,
        "status": batch.processing_status,
        "request_counts": {
            "processing": batch.request_counts.processing,
            "succeeded": batch.request_counts.succeeded,
            "errored": batch.request_counts.errored,
        },
        "created_at": batch.created_at.isoformat() if batch.created_at else None,
        "ended_at": batch.ended_at.isoformat() if batch.ended_at else None,
    }


async def retrieve_batch_results(batch_id: str) -> list[dict]:
    """
    Retrieve and parse results from a completed batch job.
    Returns a list of result dicts keyed by custom_id (= alert_id or CVE_id).

    Results are streamed from the API as an async iterator to avoid loading all
    results into memory at once. For a batch of 10,000 alerts, streaming is
    necessary to avoid OOM errors. Each result is processed and appended as it arrives.
    """
    results = []
    async for result in await client.messages.batches.results(batch_id):
        if result.result.type == "succeeded":
            content = result.result.message.content[0].text
            try:
                # Parse JSON responses. If the model ignored the JSON-only instruction
                # and added prose, json.loads will fail and we store the raw text.
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = {"raw": content}
            results.append({"id": result.custom_id, "result": parsed, "status": "succeeded"})
        else:
            # Non-success types: "errored" (model error), "canceled", "expired" (batch TTL exceeded).
            results.append({
                "id": result.custom_id,
                "status": result.result.type,
                "error": getattr(result.result, "error", {})
            })

    logger.info(f"[Batch] Retrieved {len(results)} results for batch {batch_id}")
    return results
