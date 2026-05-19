"""
Alerts API Routes

Techniques implemented at the API layer:
  - Semantic deduplication: checks new alerts against recent ones before pipeline entry
  - ML anomaly pre-filter: scores alerts before pipeline; low-anomaly alerts auto-closed
  - SSE streaming: GET /alerts/{id}/stream streams pipeline progress in real time
  - HITL approval: POST /alerts/{id}/approve resumes paused CRITICAL pipelines
"""

import asyncio
import uuid
import json
from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from app.models.schemas import AlertCreate, AlertResponse, IncidentReport, AlertStatus
from app.agents.supervisor import process_alert, resume_pipeline
from app.services.deduplication import check_duplicate
from app.services.anomaly_detection import score_alert

router = APIRouter()

# In-memory stores for development - swap for PostgreSQL in production
_alerts: dict[str, AlertResponse] = {}
_incidents: dict[str, IncidentReport] = {}
_pipeline_events: dict[str, list[str]] = {}  # alert_id -> list of SSE event strings
_duplicate_counts: dict[str, int] = {}        # original_alert_id -> duplicate count


def _emit_event(alert_id: str, event_type: str, data: dict) -> None:
    """Append a pipeline progress event for SSE streaming."""
    if alert_id not in _pipeline_events:
        _pipeline_events[alert_id] = []
    payload = json.dumps({"event": event_type, "data": data, "ts": datetime.utcnow().isoformat()})
    _pipeline_events[alert_id].append(f"data: {payload}\n\n")


# ─── POST /alerts/ ────────────────────────────────────────────────────────────

@router.post("/", response_model=AlertResponse, status_code=202)
async def create_alert(alert: AlertCreate, background_tasks: BackgroundTasks):
    """
    Ingest a new security alert.

    Pre-pipeline checks (in order):
      1. Semantic deduplication - is this alert too similar to a recent one?
      2. ML anomaly scoring - is this statistically anomalous enough to investigate?

    If both pass, the multi-agent pipeline runs in the background.
    Returns 202 immediately with the alert ID for status polling or SSE streaming.
    """
    alert_id = str(uuid.uuid4())
    now = datetime.utcnow()

    # ── Step 1: Semantic deduplication ────────────────────────────────────────
    is_dup, original_id = await check_duplicate(alert_id, alert.title, alert.description)
    if is_dup and original_id:
        _duplicate_counts[original_id] = _duplicate_counts.get(original_id, 1) + 1
        # Return the original alert with updated duplicate count
        if original_id in _alerts:
            original = _alerts[original_id]
            _emit_event(original_id, "duplicate_detected", {
                "duplicate_count": _duplicate_counts[original_id]
            })
            return original
        # Fall through if original not found (edge case)

    # ── Step 2: ML anomaly pre-filter ─────────────────────────────────────────
    anomaly_score, is_anomaly = await score_alert(alert)
    status = AlertStatus.NEW

    if not is_anomaly:
        # Low anomaly score - auto-close without running the pipeline
        status = AlertStatus.FALSE_POSITIVE
        alert_response = AlertResponse(
            **alert.model_dump(),
            id=alert_id,
            status=status,
            created_at=now,
            updated_at=now,
        )
        _alerts[alert_id] = alert_response
        _emit_event(alert_id, "auto_closed", {
            "reason": "low_anomaly_score",
            "anomaly_score": anomaly_score,
        })
        return alert_response

    # ── Normal flow: queue the full agent pipeline ─────────────────────────────
    alert_response = AlertResponse(
        **alert.model_dump(),
        id=alert_id,
        status=AlertStatus.NEW,
        created_at=now,
        updated_at=now,
    )
    _alerts[alert_id] = alert_response
    _emit_event(alert_id, "pipeline_queued", {"anomaly_score": anomaly_score})

    background_tasks.add_task(_run_pipeline, alert_id, alert, anomaly_score)
    return alert_response


# ─── GET /alerts/ ─────────────────────────────────────────────────────────────

@router.get("/", response_model=list[AlertResponse])
async def list_alerts():
    return list(_alerts.values())


# ─── GET /alerts/{id} ─────────────────────────────────────────────────────────

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    alert = _alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


# ─── GET /alerts/{id}/incident ────────────────────────────────────────────────

@router.get("/{alert_id}/incident", response_model=IncidentReport)
async def get_alert_incident(alert_id: str):
    incident = _incidents.get(alert_id)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident report not yet available - pipeline may still be running",
        )
    return incident


# ─── GET /alerts/{id}/stream (SSE Streaming) ──────────────────────────────────

@router.get("/{alert_id}/stream")
async def stream_alert_pipeline(alert_id: str):
    """
    Stream pipeline progress events via Server-Sent Events (SSE).

    The client connects once and receives real-time updates as each agent
    completes its work, rather than polling the API repeatedly.

    Events emitted:
      pipeline_queued     - alert accepted, pipeline starting
      agent_started       - an agent began processing
      agent_completed     - an agent finished with its output summary
      duplicate_detected  - alert was a duplicate of an existing one
      auto_closed         - alert was below anomaly threshold
      pipeline_complete   - full incident report ready
      pipeline_error      - something failed

    Usage:
      const es = new EventSource('/api/v1/alerts/{id}/stream');
      es.onmessage = (e) => console.log(JSON.parse(e.data));
    """
    if alert_id not in _alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    async def event_generator():
        sent_index = 0
        timeout_seconds = 120
        elapsed = 0

        while elapsed < timeout_seconds:
            events = _pipeline_events.get(alert_id, [])
            while sent_index < len(events):
                yield events[sent_index]
                sent_index += 1

            # Check if pipeline is done
            alert = _alerts.get(alert_id)
            if alert and alert.status in (AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE):
                yield f"data: {json.dumps({'event': 'stream_end', 'data': {}})}\n\n"
                break

            await asyncio.sleep(0.5)
            elapsed += 0.5

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ─── POST /alerts/{id}/approve (HITL) ─────────────────────────────────────────

@router.post("/{alert_id}/approve", response_model=dict)
async def approve_critical_alert(alert_id: str, background_tasks: BackgroundTasks):
    """
    Resume a CRITICAL alert pipeline that was paused for human-in-the-loop approval.
    Called by an analyst after reviewing the triage and threat intel findings.
    """
    alert = _alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status != AlertStatus.TRIAGING:
        raise HTTPException(
            status_code=400,
            detail=f"Alert is not awaiting approval (current status: {alert.status})",
        )

    _emit_event(alert_id, "hitl_approved", {"approved_by": "analyst"})
    background_tasks.add_task(_resume_hitl_pipeline, alert_id)
    return {"status": "approved", "alert_id": alert_id, "message": "Pipeline resuming"}


# ─── Background tasks ──────────────────────────────────────────────────────────

async def _run_pipeline(alert_id: str, alert: AlertCreate, anomaly_score: float):
    """Background task: run the full multi-agent SOC pipeline."""
    try:
        _alerts[alert_id].status = AlertStatus.TRIAGING
        _emit_event(alert_id, "agent_started", {"agent": "triage"})

        incident = await process_alert(alert_id, alert, anomaly_score)

        _incidents[alert_id] = incident
        _alerts[alert_id].status = AlertStatus.CLOSED
        _alerts[alert_id].severity = incident.severity
        _emit_event(alert_id, "pipeline_complete", {
            "incident_id": incident.incident_id,
            "severity": incident.severity.value,
        })
    except Exception as e:
        _alerts[alert_id].status = AlertStatus.NEW
        _emit_event(alert_id, "pipeline_error", {"error": str(e)})
        raise e


async def _resume_hitl_pipeline(alert_id: str):
    """Background task: resume a HITL-paused pipeline after analyst approval."""
    try:
        incident = await resume_pipeline(alert_id)
        _incidents[alert_id] = incident
        _alerts[alert_id].status = AlertStatus.CLOSED
        _alerts[alert_id].severity = incident.severity
        _emit_event(alert_id, "pipeline_complete", {
            "incident_id": incident.incident_id,
            "severity": incident.severity.value,
        })
    except Exception as e:
        _emit_event(alert_id, "pipeline_error", {"error": str(e)})
        raise e
