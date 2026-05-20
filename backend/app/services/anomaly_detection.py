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

How Isolation Forest works conceptually:
  Build many random decision trees. For each sample, count how many random
  splits (tree depth) it takes to isolate it into its own leaf node. Anomalous
  points are structurally different from the bulk and get isolated in fewer
  splits (shorter path length = high anomaly score). Normal points blend into
  the crowd and require more splits to isolate. Think of it as: the easier it is
  to single out a data point, the more suspicious it is.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import hashlib
import logging
from app.config import settings

logger = logging.getLogger(__name__)

# Global model and scaler trained incrementally as alerts arrive.
# The model starts in pass-through mode (all alerts treated as anomalies)
# until MIN_TRAINING_SAMPLES are collected. This cold-start is intentional:
# better to run the expensive LLM pipeline on early alerts than to reject
# legitimate incidents before the model has learned what "normal" looks like.
_model: IsolationForest | None = None
_scaler: StandardScaler | None = None
_training_buffer: list[list[float]] = []
MIN_TRAINING_SAMPLES = 20


# === Feature Extraction ===

def _extract_features(alert) -> list[float]:
    """
    Extract numerical features from an alert for anomaly scoring.
    Features are designed to capture statistical rareness, not semantic meaning.

    Isolation Forest operates on numbers, not text. We convert alert metadata
    into a 10-dimensional vector that captures structural properties. The model
    learns what "typical" alerts look like in this feature space and flags
    structural outliers. Note: this does NOT capture semantic meaning of the
    title/description - that is the LLM's job.

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
        # Map the source system name to a stable float in [0,1]. This lets the
        # model learn that alerts from "EDR" have different normal patterns than
        # alerts from "Firewall" without needing one-hot encoding.
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


# === Model Training ===

def _train_model() -> None:
    """Train or retrain the Isolation Forest on buffered samples.

    StandardScaler is applied before fitting because Isolation Forest uses random
    splits on feature value ranges. Without scaling, features with large ranges
    (e.g., description_length 0-500) would dominate over binary features (0/1),
    skewing which splits the trees make.

    contamination is the expected fraction of anomalies in the data. Setting it
    to anomaly_threshold (default 0.15) tells the model that ~15% of alerts are
    expected to be anomalous, calibrating the decision boundary accordingly.
    """
    global _model, _scaler

    if len(_training_buffer) < MIN_TRAINING_SAMPLES:
        return

    X = np.array(_training_buffer)
    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)

    _model = IsolationForest(
        contamination=settings.anomaly_threshold,
        n_estimators=100,       # More trees = more stable scores, diminishing returns above 200
        random_state=42,        # Fixed seed for reproducibility across retrains
        n_jobs=-1,              # Parallelize tree building across all CPU cores
    )
    _model.fit(X_scaled)
    logger.info(f"[AnomalyDetection] Model trained on {len(_training_buffer)} samples")


# === Alert Scoring ===

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
    # Add this alert's features to the training buffer. The model periodically
    # retrains itself as it sees more data, improving its baseline over time.
    _training_buffer.append(features)

    # Retrain every 50 new alerts. More frequent retraining keeps the baseline
    # current but is computationally expensive; 50 is a reasonable trade-off.
    if len(_training_buffer) % 50 == 0:
        _train_model()

    if _model is None or _scaler is None:
        # Pass-through before model is ready: do not filter anything.
        logger.debug("[AnomalyDetection] Model not yet trained, passing alert through")
        return 1.0, True

    X = np.array([features])
    X_scaled = _scaler.transform(X)

    # score_samples returns the anomaly score as a negative value where more
    # negative = more anomalous (Isolation Forest's internal convention).
    # We invert and shift to produce an intuitive 0-1 score where 1 = most anomalous.
    raw_score = _model.score_samples(X_scaled)[0]
    normalized = float(1.0 - (raw_score + 0.5))
    normalized = max(0.0, min(1.0, normalized))

    # predict() returns -1 for anomaly, 1 for normal. We use this binary label
    # as the gate: -1 means "send to LLM pipeline," 1 means "auto-close."
    prediction = _model.predict(X_scaled)[0]
    is_anomaly = prediction == -1

    logger.info(
        f"[AnomalyDetection] Alert '{alert.title[:40]}' score={normalized:.3f} "
        f"is_anomaly={is_anomaly}"
    )
    return normalized, is_anomaly
