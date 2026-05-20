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

Why this matters for a SOC:
  Without memory, every alert is analyzed in a vacuum. A known-bad IP that
  appeared in three previous incidents looks the same as a never-seen IP.
  With memory, the investigation agent opens its analysis already knowing
  "this IP was associated with a CRITICAL ransomware incident 12 days ago."
  This is the difference between a new analyst and an experienced one.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Memory entries older than 90 days are considered stale and excluded from recall.
# This prevents ancient incidents from flooding the context with outdated data.
# In a fast-moving threat landscape, a C2 IP from 6 months ago may now host
# legitimate content. 90 days is a conservative but reasonable TTL.
MEMORY_TTL_DAYS = 90

# Limit stored entries per entity to prevent unbounded growth. Only the most
# recent MAX_MEMORIES_PER_ENTITY incidents are kept; older ones are evicted.
MAX_MEMORIES_PER_ENTITY = 10

# In-memory store for development. In production, replace with PostgreSQL:
# the key becomes a primary key, the list becomes rows in an `entity_memories` table.
# PostgreSQL also enables querying by time range, severity, or MITRE technique.
_memory_store: dict[str, list[dict]] = {}


# === Internal Helpers ===

def _entity_key(entity_type: str, value: str) -> str:
    """Build a normalized lookup key for an entity.

    Normalizing to lowercase and stripping whitespace ensures that "IP:1.2.3.4",
    "ip:1.2.3.4", and "ip: 1.2.3.4" all resolve to the same memory bucket.
    """
    return f"{entity_type}:{value.lower().strip()}"


# === Write ===

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

    New entries are prepended (insert at index 0) so that recall always
    sees the most recent incidents first when we slice to [:3] in recall_memories.
    The list is then truncated to MAX_MEMORIES_PER_ENTITY to prevent unbounded growth.
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

    # Insert at front so index 0 is always the most recent incident.
    _memory_store[key].insert(0, entry)
    # Trim to MAX_MEMORIES_PER_ENTITY: keep only the most recent N entries.
    _memory_store[key] = _memory_store[key][:MAX_MEMORIES_PER_ENTITY]
    logger.info(f"[Memory] Stored memory for {key}")


# === Read ===

async def recall_memories(entities: list[tuple[str, str]]) -> str:
    """
    Retrieve memory entries for a list of (entity_type, entity_value) tuples.
    Returns a formatted context string for injection into agent prompts.

    The returned string is included verbatim in the investigation agent's prompt
    under "=== Agent Memory (Prior Incidents) ===". It should be concise enough
    not to crowd out the current alert's own data, so we cap at 3 memories per entity.

    Example entities: [("ip", "203.0.113.42"), ("host", "WORKSTATION-042")]
    """
    now = datetime.utcnow()
    results = []

    for entity_type, entity_value in entities:
        key = _entity_key(entity_type, entity_value)
        entries = _memory_store.get(key, [])

        # Filter expired entries. We check at read time rather than write time
        # to avoid a background cleanup job. The TTL is enforced lazily.
        valid = [
            e for e in entries
            if datetime.fromisoformat(e["expires_at"]) > now
        ]

        if not valid:
            continue

        results.append(f"Past activity for {entity_type} '{entity_value}':")
        # Show only the 3 most recent incidents to keep the context compact.
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


# === Entity Extraction ===

async def extract_entities_from_alert(alert) -> list[tuple[str, str]]:
    """
    Extract entity (type, value) pairs from an alert for memory lookup.

    This is a lightweight heuristic extraction: IPs from structured fields,
    plus a simple check for IOCs that look like IPs or domains. For production,
    you would want a proper NLP entity extractor or regex-based IOC parser here
    to handle file hashes, email addresses, and other entity types.
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
            # Heuristic: if the IOC has dots and digits only, treat as IP; otherwise domain.
            entities.append(("ip" if ioc.replace(".", "").isdigit() else "domain", ioc))
    return entities
