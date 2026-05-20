"""
Alert Deduplication and Clustering Service

Two techniques implemented here:

1. Semantic Deduplication
   Before a new alert enters the pipeline, embed it and check cosine similarity
   against alerts from the last N minutes. If similarity exceeds the threshold,
   it is a duplicate - increment a counter instead of spawning a new pipeline.
   Prevents alert storms from running hundreds of identical agent pipelines.

2. Alert Clustering
   Groups semantically similar alerts using DBSCAN on their embeddings.
   Run periodically (e.g. every 5 minutes) to identify coordinated campaigns.
   A cluster of 50 brute-force alerts becomes one representative alert with a count.
"""

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import normalize
from datetime import datetime, timedelta
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# In-memory store for recent alert embeddings. Swap for Redis in production.
# Structure: list of {"alert_id": str, "embedding": list[float], "timestamp": datetime, "title": str}
# Redis is better for production because it survives worker restarts and is shared
# across multiple API server instances, whereas this in-memory store is per-process.
_recent_embeddings: list[dict] = {}
DEDUP_WINDOW_MINUTES = 30


# === Cosine Similarity ===

def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two embedding vectors.

    Cosine similarity measures the angle between two vectors, not their magnitude.
    This is the right metric for embeddings because two semantically identical
    sentences may have different vector magnitudes depending on length, but their
    directions (angles) will be nearly identical. Range: -1 (opposite) to 1 (identical).
    Practical threshold for "same alert": ~0.92+.
    """
    va = np.array(a)
    vb = np.array(b)
    denom = np.linalg.norm(va) * np.linalg.norm(vb)
    if denom == 0:
        return 0.0
    return float(np.dot(va, vb) / denom)


# === Embedding ===

async def embed_alert(alert_text: str) -> list[float] | None:
    """
    Generate an embedding for alert text using Voyage-3.
    Returns None if embedding fails so deduplication degrades gracefully.

    Voyage-3 is Anthropic's semantic embedding model. It maps text to a 1024-
    dimensional vector where semantically similar texts cluster together. The
    embedding captures meaning rather than exact phrasing, so "blocked outbound
    connection to known C2" and "outbound traffic to C2 infrastructure blocked"
    will have very high cosine similarity even though the words differ.
    """
    try:
        from langchain_community.embeddings import VoyageEmbeddings
        from app.config import settings
        embedder = VoyageEmbeddings(
            voyage_api_key=settings.anthropic_api_key,
            model="voyage-3"
        )
        return embedder.embed_query(alert_text)
    except Exception as e:
        logger.warning(f"[Dedup] Embedding failed: {e}")
        # Return None rather than raising: if the embedding service is down,
        # we pass all alerts through rather than blocking the pipeline entirely.
        return None


# === Duplicate Check ===

async def check_duplicate(alert_id: str, alert_title: str, alert_description: str) -> tuple[bool, str | None]:
    """
    Check if an incoming alert is semantically duplicate of a recent one.

    Semantic deduplication works differently from exact deduplication (hash matching):
    it catches rephrased, reformatted, or slightly varied versions of the same event.
    A SIEM might generate "Brute force from 1.2.3.4" and "Multiple failed logins
    from 1.2.3.4" for the same attack. Exact matching misses this; cosine similarity catches it.

    Returns:
        (is_duplicate, original_alert_id)
        If is_duplicate is True, the caller should skip the pipeline and
        increment the duplicate count on original_alert_id instead.
    """
    if not settings.enable_deduplication:
        return False, None

    alert_text = f"{alert_title} {alert_description}"
    embedding = await embed_alert(alert_text)
    if embedding is None:
        return False, None

    cutoff = datetime.utcnow() - timedelta(minutes=DEDUP_WINDOW_MINUTES)
    # Only compare against recent alerts. An alert from 2 hours ago that looks
    # identical is probably a recurring event, not a duplicate - it should spawn
    # its own pipeline for fresh analysis.
    recent = [e for e in _recent_embeddings if e["timestamp"] > cutoff]

    for candidate in recent:
        sim = cosine_similarity(embedding, candidate["embedding"])
        if sim >= settings.dedup_similarity_threshold:
            logger.info(
                f"[Dedup] Alert '{alert_title[:50]}' is duplicate of "
                f"'{candidate['alert_id']}' (similarity={sim:.3f})"
            )
            return True, candidate["alert_id"]

    # Not a duplicate: store this embedding for future checks.
    _recent_embeddings.append({
        "alert_id": alert_id,
        "embedding": embedding,
        "timestamp": datetime.utcnow(),
        "title": alert_title,
    })
    # Evict expired entries to prevent unbounded memory growth.
    _recent_embeddings[:] = [e for e in _recent_embeddings if e["timestamp"] > cutoff]

    return False, None


# === Alert Clustering ===

def cluster_alerts(alert_embeddings: list[dict]) -> list[list[str]]:
    """
    Cluster a list of alerts by semantic similarity using DBSCAN.

    DBSCAN (Density-Based Spatial Clustering of Applications with Noise):
    Unlike k-means, DBSCAN does not require you to specify the number of clusters
    upfront. It discovers clusters of arbitrary shape wherever embeddings are dense.
    Points that do not belong to any dense region are labeled as "noise" (label -1).
    This is ideal for alert data because you do not know in advance how many attack
    campaigns are active.

    A cluster of 50 SSH brute-force alerts pointing at the same host is discovered
    automatically and can be surfaced as one coordinated campaign rather than 50
    independent incidents. The ops team gets one ticket instead of fifty.

    Args:
        alert_embeddings: list of {"alert_id": str, "embedding": list[float]}

    Returns:
        List of clusters, each cluster is a list of alert_ids.
        Noise points (DBSCAN label -1) are returned as singleton clusters.

    DBSCAN parameters:
        eps=0.15 - maximum cosine distance within a cluster (lower = tighter clusters)
        min_samples=2 - minimum 2 alerts to form a cluster (singletons are noise)
    """
    if len(alert_embeddings) < 2:
        return [[a["alert_id"]] for a in alert_embeddings]

    embeddings = np.array([a["embedding"] for a in alert_embeddings])
    # L2 normalize before using cosine metric so DBSCAN's distance computation
    # is equivalent to cosine distance. Normalized vectors: cosine_dist = 1 - cosine_sim.
    embeddings = normalize(embeddings)

    db = DBSCAN(eps=0.15, min_samples=2, metric="cosine")
    labels = db.fit_predict(embeddings)

    clusters: dict[int, list[str]] = {}
    for i, label in enumerate(labels):
        clusters.setdefault(label, []).append(alert_embeddings[i]["alert_id"])

    # Separate noise points (-1) into individual singletons so every alert_id
    # appears in exactly one output group, whether clustered or alone.
    result = []
    for label, alert_ids in clusters.items():
        if label == -1:
            result.extend([[aid] for aid in alert_ids])
        else:
            result.append(alert_ids)

    logger.info(f"[Clustering] {len(alert_embeddings)} alerts -> {len(result)} clusters")
    return result
