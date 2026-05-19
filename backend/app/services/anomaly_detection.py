"""
ML Anomaly Detection Pre-Filter

An Isolation Forest model runs on raw alert feature vectors before the LLM
pipeline. It assigns an anomaly score to each alert. Only alerts above the
threshold enter the full multi-agent pipeline - low-anomaly alerts are
auto-closed without burning LLM tokens.

Why Isolation Forest?
- Unsupervised: no labeled training data required
- Fast inference: suitable for real-time pre-filtering
- Interpretable: anomaly score is a meaningful 0-1 value
- Handles high-dimensional sparse features well

This demonstrates the production pattern of hybrid ML + LLM systems,
where classical ML handles the high-volume triage and LLMs handle
the complex reasoning on a smaller filtered set.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import hashlib
import logging
from app.config import settings

logger = logging.getLogger(__name__)

# Global model and scaler - trained incrementally as alerts arrive
_model: IsolationForest | None = None
_scaler: StandardScaler | None = None
_training_buffer: list[list[float]] = []
MIN_TRAINING_SAMPLES = 20  # Minimum alerts before model is trained


def _extract_features(alert) -> list[float]:
    """
    Extract numerical features from an alert for anomaly scoring.
    Features are designed to capture statistical rareness, not semantic meaning.

    Feature vector (10 dimensions):
    0: Source IP entropy (0=private/loopback, 1=public)
    1: Destination port (normalized 0-1)
    2: Has IOCs (0/1)
    3: IOC count (normalized)
    4: Description length (normalized)
    5: Title length (normalized)
    6: Source hash bucket (maps source system to a number)
    7: Has source IP (0/1)
    8: Has destination IP (0/1)
    9: Has raw log (0/1)
    """
    def ip_is_public(ip: str | None) -> float:
        if not ip:
            return 0.0
        private_prefixes = ("10.", "192.168.", "172.16.", "127.", "::1")
        return 0.0 if any(ip.startswith(p) for p in private_prefixes) else 1.0

    def normalize_port(ip: str | None) -> float:
        if not ip:
            return 0.0
        try:
            parts = ip.split(":")
            if len(parts) > 1:
                return min(int(parts[-1]) / 65535, 1.0)
        except Exception:
            pass
        return 0.5

    def source_hash(source: str) -> float:
        h = int(hashlib.md5(source.lower().encode()).hexdigest(), 16)
        return (h % 100) / 100.0

    return [
        ip_is_public(alert.source_ip),
        normalize_port(alert.destination_ip),
        1.0 if alert.iocs else 0.0,
        min(len(alert.iocs or []) / 10.0, 1.0),
        min(len(alert.description) / 500.0, 1.0),
        min(len(alert.title) / 100.0, 1.0),
        source_hash(alert.source),
        1.0 if alert.source_ip else 0.0,
        1.0 if alert.destination_ip else 0.0,
        1.0 if alert.raw_log else 0.0,
    ]


def _train_model() -> None:
    """Train or retrain the Isolation Forest on buffered samples."""
    global _model, _scaler

    if len(_training_buffer) < MIN_TRAINING_SAMPLES:
        return

    X = np.array(_training_buffer)
    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)

    _model = IsolationForest(
        contamination=settings.anomaly_threshold,
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )
    _model.fit(X_scaled)
    logger.info(f"[AnomalyDetection] Model trained on {len(_training_buffer)} samples")


async def score_alert(alert) -> tuple[float, bool]:
    """
    Score an alert for anomaly. Returns (score, is_anomaly).

    Score is 0.0-1.0 where higher = more anomalous.
    is_anomaly=True means the alert should enter the full agent pipeline.
    is_anomaly=False means it can be auto-closed or deprioritized.

    Before the model has enough training data (< MIN_TRAINING_SAMPLES),
    all alerts are treated as anomalies (pass-through mode).
    """
    if not settings.enable_anomaly_filter:
        return 1.0, True

    features = _extract_features(alert)
    _training_buffer.append(features)

    # Retrain every 50 new alerts
    if len(_training_buffer) % 50 == 0:
        _train_model()

    if _model is None or _scaler is None:
        logger.debug("[AnomalyDetection] Model not yet trained, passing alert through")
        return 1.0, True

    X = np.array([features])
    X_scaled = _scaler.transform(X)

    # Isolation Forest score: negative values = more anomalous
    raw_score = _model.score_samples(X_scaled)[0]
    # Normalize to 0-1 where 1 = most anomalous
    normalized = float(1.0 - (raw_score + 0.5))
    normalized = max(0.0, min(1.0, normalized))

    prediction = _model.predict(X_scaled)[0]  # -1 = anomaly, 1 = normal
    is_anomaly = prediction == -1

    logger.info(
        f"[AnomalyDetection] Alert '{alert.title[:40]}' score={normalized:.3f} "
        f"is_anomaly={is_anomaly}"
    )
    return normalized, is_anomaly
