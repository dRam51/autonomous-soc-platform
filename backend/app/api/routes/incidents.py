from fastapi import APIRouter, HTTPException
from app.models.schemas import IncidentReport
from app.api.routes.alerts import _incidents

router = APIRouter()


@router.get("/", response_model=list[IncidentReport])
async def list_incidents():
    """List all generated incident reports."""
    return list(_incidents.values())


@router.get("/{incident_id}", response_model=IncidentReport)
async def get_incident(incident_id: str):
    """Get a specific incident report."""
    incident = next(
        (i for i in _incidents.values() if i.incident_id == incident_id), None
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
