"""
Batch Processing Tasks

Uses Anthropic's Batch API for non-urgent, high-volume workloads where
cost matters more than latency. Batch requests are ~50% cheaper than
real-time API calls and processed asynchronously within 24 hours.

Use cases:
  - Overnight threat hunt: re-analyze historical alerts with updated prompts
  - Bulk CVE enrichment: enrich a batch of CVEs with threat context
  - Retroactive severity re-scoring: re-triage old alerts after prompt improvements
  - Corpus summarization: summarize new threat reports for RAG ingestion

How Anthropic Batch API works:
  1. Submit a list of requests as a batch job
  2. Get a batch_id back immediately
  3. Poll until complete (or use webhooks)
  4. Retrieve results by batch_id
"""

import anthropic
import json
from datetime import datetime
from app.config import settings
from app.models.schemas import AlertCreate
import logging

logger = logging.getLogger(__name__)
client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)


async def batch_retriage_alerts(alerts: list[dict]) -> str:
    """
    Submit a batch of historical alerts for re-triage using the Anthropic Batch API.
    Returns a batch_id to poll for results.

    Use this for:
      - Retroactive severity re-scoring after prompt improvements
      - Overnight re-analysis of low-confidence triage decisions
      - Bulk analysis of imported historical incidents

    Args:
        alerts: list of dicts with keys: alert_id, title, description, source, iocs

    Returns:
        batch_id: string identifier to retrieve results later
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
                custom_id=alert.get("alert_id", f"alert_{len(requests)}"),
                params=anthropic.types.MessageCreateParamsNonStreaming(
                    model="claude-haiku-4-5",  # Use Haiku for batch cost efficiency
                    max_tokens=256,
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
        )

    batch = await client.messages.batches.create(requests=requests)
    logger.info(f"[Batch] Submitted {len(requests)} alerts for re-triage. Batch ID: {batch.id}")
    return batch.id


async def batch_enrich_cves(cve_ids: list[str]) -> str:
    """
    Submit a batch of CVE IDs for threat context enrichment.
    Returns a batch_id to poll for results.

    Use this to pre-enrich your knowledge base with LLM-generated summaries
    of CVE threat context, which can then be indexed into Pinecone.
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


async def get_batch_status(batch_id: str) -> dict:
    """Check the status of a submitted batch job."""
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
    Returns a list of result dicts keyed by custom_id.
    """
    results = []
    async for result in await client.messages.batches.results(batch_id):
        if result.result.type == "succeeded":
            content = result.result.message.content[0].text
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = {"raw": content}
            results.append({"id": result.custom_id, "result": parsed, "status": "succeeded"})
        else:
            results.append({
                "id": result.custom_id,
                "status": result.result.type,
                "error": getattr(result.result, "error", {})
            })

    logger.info(f"[Batch] Retrieved {len(results)} results for batch {batch_id}")
    return results
