"""
Confidence Calibration Service

Tracks triage predictions vs. analyst-confirmed outcomes to measure and
improve confidence score accuracy over time.

A well-calibrated model means: when the Triage agent says 0.9 confidence,
it should be right ~90% of the time. Poor calibration means scores are
misleading - either over-confident (says 0.9, right only 60%) or
under-confident (says 0.5, right 90%).

How calibration works:
  1. Each triage result records (predicted_severity, confidence_score)
  2. When an analyst closes/adjusts an incident, we record the true_severity
  3. Periodically compute calibration metrics across all closed incidents
  4. Surface miscalibrated confidence bands (e.g. "0.8-0.9 band is only 65% accurate")

This data feeds back into:
  - Dynamic few-shot example selection (surface high-confidence-but-wrong examples)
  - Routing thresholds (e.g. require human review if confidence < calibrated_threshold)
  - Prompt improvement signals

Why calibration matters for a SOC:
  If the model says 90% confident on every alert regardless of actual accuracy, analysts
  stop trusting the scores. Calibration tells you whether to act on confidence numbers
  or treat them as noise. A perfectly calibrated system is like a weather forecaster
  who says "70% chance of rain" and is right on 70% of those days.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


# === Data Model ===

@dataclass
class TriagePrediction:
    alert_id: str
    predicted_severity: str
    confidence: float
    true_severity: str | None = None         # Set when an analyst closes the incident
    analyst_confirmed: bool = False          # True once an analyst has verified the outcome
    recorded_at: datetime = field(default_factory=datetime.utcnow)


# In-memory store: swap for PostgreSQL in production so calibration data persists
# across restarts and accumulates over months of operation.
_predictions: dict[str, TriagePrediction] = {}


# === Record Functions ===

def record_prediction(alert_id: str, predicted_severity: str, confidence: float) -> None:
    """Record a triage prediction for later calibration evaluation.

    Called immediately after each triage run so we have a record of what the model
    predicted before any analyst feedback. This is the "before" snapshot.
    """
    _predictions[alert_id] = TriagePrediction(
        alert_id=alert_id,
        predicted_severity=predicted_severity,
        confidence=confidence,
    )


def record_outcome(alert_id: str, true_severity: str, analyst_confirmed: bool = True) -> None:
    """Record the analyst-confirmed true severity for a closed alert.

    Called when an analyst closes or adjusts an incident. This is the "after" snapshot
    that enables calibration comparison. If the predicted and true severities match,
    the prediction was correct for this confidence band.
    """
    if alert_id in _predictions:
        _predictions[alert_id].true_severity = true_severity
        _predictions[alert_id].analyst_confirmed = analyst_confirmed
        logger.debug(f"[Calibration] Outcome recorded for {alert_id}: {true_severity}")


# === Calibration Report ===

def compute_calibration_report() -> dict:
    """
    Compute calibration metrics across all closed predictions.

    Confidence banding works like reliability diagrams in meteorology: group all
    predictions by stated confidence level and check what fraction of each group
    was actually correct. If the 90% confidence band has 60% accuracy, the model
    is systematically overconfident on high-confidence predictions.

    Returns a dict with:
      - overall_accuracy: % of predictions where severity matched
      - confidence_bands: accuracy per confidence band (0-0.5, 0.5-0.7, 0.7-0.9, 0.9-1.0)
      - severity_accuracy: accuracy per severity level
      - total_evaluated: number of confirmed incidents analyzed
      - miscalibrated_bands: bands where |predicted_accuracy - confidence_midpoint| > 0.15
    """
    # Only evaluate incidents where an analyst has confirmed the outcome.
    # Unconfirmed outcomes would skew the calibration data.
    confirmed = [p for p in _predictions.values() if p.analyst_confirmed and p.true_severity]

    if not confirmed:
        return {"status": "insufficient_data", "total_evaluated": 0}

    total = len(confirmed)
    correct = sum(1 for p in confirmed if p.predicted_severity == p.true_severity)
    overall_accuracy = correct / total

    # === Confidence Band Analysis ===
    # Group predictions into four bands. The midpoint of each band is what the model
    # "claims" as expected accuracy for predictions in that range.
    bands = {"0.0-0.5": [], "0.5-0.7": [], "0.7-0.9": [], "0.9-1.0": []}
    for p in confirmed:
        is_correct = p.predicted_severity == p.true_severity
        if p.confidence < 0.5:
            bands["0.0-0.5"].append(is_correct)
        elif p.confidence < 0.7:
            bands["0.5-0.7"].append(is_correct)
        elif p.confidence < 0.9:
            bands["0.7-0.9"].append(is_correct)
        else:
            bands["0.9-1.0"].append(is_correct)

    # Midpoints represent the expected accuracy for each band. A 0.9-1.0 confidence
    # band should be correct ~95% of the time if well-calibrated.
    band_midpoints = {"0.0-0.5": 0.25, "0.5-0.7": 0.6, "0.7-0.9": 0.8, "0.9-1.0": 0.95}
    confidence_bands = {}
    miscalibrated = []

    for band, results in bands.items():
        if not results:
            continue
        accuracy = sum(results) / len(results)
        midpoint = band_midpoints[band]
        # A gap >0.15 means the model is meaningfully miscalibrated in this band.
        # E.g., the 0.9-1.0 band being only 70% accurate (gap=0.25) is actionable.
        gap = abs(accuracy - midpoint)
        confidence_bands[band] = {
            "count": len(results),
            "accuracy": round(accuracy, 3),
            "expected_accuracy": midpoint,
            "calibration_gap": round(gap, 3),
        }
        if gap > 0.15:
            miscalibrated.append(band)

    # === Per-Severity Accuracy ===
    # A model might be well-calibrated overall but systematically wrong on "low"
    # severity (e.g., it under-classifies medium alerts as low). Per-severity
    # breakdown exposes these systematic biases for prompt tuning.
    severity_buckets: dict[str, list[bool]] = defaultdict(list)
    for p in confirmed:
        severity_buckets[p.predicted_severity].append(
            p.predicted_severity == p.true_severity
        )
    severity_accuracy = {
        sev: round(sum(results) / len(results), 3)
        for sev, results in severity_buckets.items()
        if results
    }

    return {
        "status": "ok",
        "total_evaluated": total,
        "overall_accuracy": round(overall_accuracy, 3),
        "confidence_bands": confidence_bands,
        "severity_accuracy": severity_accuracy,
        "miscalibrated_bands": miscalibrated,
        "recommendation": (
            f"Bands {miscalibrated} are miscalibrated (>15% gap). "
            f"Consider adjusting confidence thresholds or adding more few-shot examples "
            f"for these confidence ranges."
        ) if miscalibrated else "Model appears well-calibrated.",
    }
