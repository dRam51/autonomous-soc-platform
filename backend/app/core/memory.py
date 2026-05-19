"""
Agent Memory Module
Provides cross-session entity memory so agents can recall what happened
to an IP, hostname, or user account in past incidents.

Memory is keyed by entity (e.g. "ip:203.0.113.42", "host:WORKSTATION-042")
and stored as JSON in PostgreSQL. Entries expire after MEMORY_TTL days.

How it works:
  1. Before each pipeline run, relevant memories are fetched and injected
     into the agent's context as additional background.
  2. After a pipeline completes, the incident outcome is written back
     as a new memory entry for all entities involved.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

MEMORY_TTL_DAYS = 90
MAX_MEMORIES_PER_ENTITY = 10

# In-memory store for development. Swap for PostgreSQL in production.
_memory_store: dict[str, list[dict]] = {}


def _entity_key(entity_type: str, value: str) -> str:
    return f"{entity_type}:{value.lower().strip()}"


async def store_memory(
    entity_type: str,
    entity_value: str,
    incident_id: str,
    severity: str,
    summary: str,
    iocs: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
) -> None:
    """
    Store an incident outcome as a memory entry for a given entity.
    Called by the Reporting agent after a pipeline completes.
    """
    key = _entity_key(entity_type, entity_value)
    entry = {
        "incident_id": incident_id,
        "severity": severity,
        "summary": summary,
        "iocs": iocs or [],
        "mitre_techniques": mitre_techniques or [],
        "timestamp": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(days=MEMORY_TTL_DAYS)).isoformat(),
    }

    if key not in _memory_store:
        _memory_store[key] = []

    _memory_store[key].insert(0, entry)
    _memory_store[key] = _memory_store[key][:MAX_MEMORIES_PER_ENTITY]
    logger.info(f"[Memory] Stored memory for {key}")


async def recall_memories(entities: list[tuple[str, str]]) -> str:
    """
    Retrieve memory entries for a list of (entity_type, entity_value) tuples.
    Returns a formatted context string for injection into agent prompts.

    Example entities: [("ip", "203.0.113.42"), ("host", "WORKSTATION-042")]
    """
    now = datetime.utcnow()
    results = []

    for entity_type, entity_value in entities:
        key = _entity_key(entity_type, entity_value)
        entries = _memory_store.get(key, [])

        # Filter expired entries
        valid = [
            e for e in entries
            if datetime.fromisoformat(e["expires_at"]) > now
        ]

        if not valid:
            continue

        results.append(f"Past activity for {entity_type} '{entity_value}':")
        for e in valid[:3]:
            ts = e["timestamp"][:10]
            results.append(
                f"  [{ts}] Incident {e['incident_id'][:8]} | Severity: {e['severity'].upper()} | "
                f"{e['summary'][:150]}"
            )
            if e.get("mitre_techniques"):
                results.append(f"    TTPs: {', '.join(e['mitre_techniques'][:5])}")

    if not results:
        return "No prior activity found for the entities in this alert."

    return "Agent Memory - Prior Incident Context:\n" + "\n".join(results)


async def extract_entities_from_alert(alert) -> list[tuple[str, str]]:
    """
    Extract entity (type, value) pairs from an alert for memory lookup.
    """
    entities = []
    if alert.source_ip:
        entities.append(("ip", alert.source_ip))
    if alert.destination_ip:
        entities.append(("ip", alert.destination_ip))
    if alert.affected_host:
        entities.append(("host", alert.affected_host))
    for ioc in (alert.iocs or []):
        if "." in ioc and not ioc.startswith("$"):
            entities.append(("ip" if ioc.replace(".", "").isdigit() else "domain", ioc))
    return entities
