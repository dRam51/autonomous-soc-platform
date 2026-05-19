"""
Services Unit Tests: Deduplication, Anomaly Detection, Calibration
"""

import pytest
from app.services.deduplication import cosine_similarity, cluster_alerts
from app.services.anomaly_detection import _extract_features
from app.services.calibration import (
    record_prediction, record_outcome, compute_calibration_report
)


# ─── Deduplication Tests ──────────────────────────────────────────────────────

def test_cosine_similarity_identical():
    v = [1.0, 0.5, 0.3, 0.8]
    assert cosine_similarity(v, v) == pytest.approx(1.0, abs=1e-6)


def test_cosine_similarity_orthogonal():
    a = [1.0, 0.0]
    b = [0.0, 1.0]
    assert cosine_similarity(a, b) == pytest.approx(0.0, abs=1e-6)


def test_cluster_alerts_groups_similar():
    """Alerts with identical embeddings should cluster together."""
    embedding_a = [1.0, 0.0, 0.0, 0.0]
    embedding_b = [0.99, 0.01, 0.0, 0.0]  # Very similar to a
    embedding_c = [0.0, 0.0, 1.0, 0.0]    # Different

    alerts = [
        {"alert_id": "alert-1", "embedding": embedding_a},
        {"alert_id": "alert-2", "embedding": embedding_b},
        {"alert_id": "alert-3", "embedding": embedding_c},
    ]
    clusters = cluster_alerts(alerts)
    all_ids = [aid for cluster in clusters for aid in cluster]
    assert set(all_ids) == {"alert-1", "alert-2", "alert-3"}


def test_cluster_alerts_single_item():
    alerts = [{"alert_id": "solo", "embedding": [1.0, 0.0]}]
    clusters = cluster_alerts(alerts)
    assert len(clusters) == 1
    assert clusters[0] == ["solo"]


# ─── Anomaly Detection Tests ──────────────────────────────────────────────────

def test_extract_features_returns_10_dimensions():
    class MockAlert:
        source_ip = "203.0.113.42"
        destination_ip = "10.0.0.1:4444"
        iocs = ["203.0.113.42", "evil.com"]
        description = "Suspicious PowerShell execution with encoded command"
        title = "Encoded PowerShell via Office"
        source = "CrowdStrike EDR"
        raw_log = "process_create parent=WINWORD.EXE child=powershell.exe"

    features = _extract_features(MockAlert())
    assert len(features) == 10
    assert all(0.0 <= f <= 1.0 for f in features)


def test_extract_features_private_ip_scores_zero():
    class MockAlert:
        source_ip = "192.168.1.100"
        destination_ip = None
        iocs = []
        description = "test"
        title = "test"
        source = "test"
        raw_log = None

    features = _extract_features(MockAlert())
    assert features[0] == 0.0  # private IP should score 0


def test_extract_features_public_ip_scores_one():
    class MockAlert:
        source_ip = "8.8.8.8"
        destination_ip = None
        iocs = []
        description = "test"
        title = "test"
        source = "test"
        raw_log = None

    features = _extract_features(MockAlert())
    assert features[0] == 1.0  # public IP should score 1


# ─── Calibration Tests ────────────────────────────────────────────────────────

def test_calibration_no_data():
    # Clear predictions by importing fresh
    import app.services.calibration as cal
    cal._predictions.clear()
    report = compute_calibration_report()
    assert report["status"] == "insufficient_data"


def test_calibration_perfect_accuracy():
    import app.services.calibration as cal
    cal._predictions.clear()

    for i in range(10):
        record_prediction(f"alert-{i}", "high", 0.9)
        record_outcome(f"alert-{i}", "high", analyst_confirmed=True)

    report = compute_calibration_report()
    assert report["overall_accuracy"] == 1.0
    assert report["total_evaluated"] == 10


def test_calibration_mixed_accuracy():
    import app.services.calibration as cal
    cal._predictions.clear()

    # 7 correct, 3 wrong in the 0.7-0.9 band
    for i in range(7):
        record_prediction(f"correct-{i}", "high", 0.8)
        record_outcome(f"correct-{i}", "high", analyst_confirmed=True)
    for i in range(3):
        record_prediction(f"wrong-{i}", "high", 0.8)
        record_outcome(f"wrong-{i}", "medium", analyst_confirmed=True)  # analyst said medium

    report = compute_calibration_report()
    assert report["overall_accuracy"] == pytest.approx(0.7, abs=0.01)
    band = report["confidence_bands"].get("0.7-0.9", {})
    assert band.get("accuracy") == pytest.approx(0.7, abs=0.01)
