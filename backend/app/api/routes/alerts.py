from fastapi import APIRouter, BackgroundTasks, HTTPException
from app.models.schemas import AlertCreate, AlertResponse, IncidentReport
from app.agents.supervisor import process_alert
from datetime import datetime
import uuid

router = APIRouter()

# In-memory store for development — swap for PostgreSQL in production
_alerts: dict[str, AlertResponse] = {}
_incidents: dict[str, IncidentReport] = {}


@router.post("/", response_model=AlertResponse, status_code=202)
async def create_alert(alert: AlertCreate, background_tasks: BackgroundTasks):
    """
    Ingest a new security alert and kick off the multi-agent triage pipeline.
    Returns immediately — pipeline runs asynchronously.
    """
    alert_id = str(uuid.uuid4())
    now = datetime.utcnow()

    alert_response = AlertResponse(
        **alert.model_dump(),
        id=alert_id,
        created_at=now,
        updated_at=now,
    )
    _alerts[alert_id] = alert_response

    background_tasks.add_task(_run_pipeline, alert_id, alert)
    return alert_response


@router.get("/", response_model=list[AlertResponse])
async def list_alerts():
    """List all ingested alerts."""
    return list(_alerts.values())


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    """Get a specific alert by ID."""
    alert = _alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{alert_id}/incident", response_model=IncidentReport)
async def get_alert_incident(alert_id: str):
    """Get the incident report generated for an alert."""
    incident = _incidents.get(alert_id)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident report not yet available — pipeline may still be running",
        )
    return incident


async def _run_pipeline(alert_id: str, alert: AlertCreate):
    """Background task: run the full multi-agent SOC pipeline."""
    try:
        _alerts[alert_id].status = "triaging"
        incident = await process_alert(alert_id, alert)
        _incidents[alert_id] = incident
        _alerts[alert_id].status = "closed"
        _alerts[alert_id].severity = incident.severity
    except Exception as e:
        _alerts[alert_id].status = "new"
        raise e
