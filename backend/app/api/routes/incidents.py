"""
Incidents API Routes

Incidents are the final output of the SOC pipeline: a structured report combining
triage, threat intel, investigation, and remediation findings. These routes provide
read-only access to completed incident reports. Incidents are created automatically
by the Reporting agent - they cannot be created directly via this API.

The incidents store (_incidents) is imported from the alerts module because that is
where the pipeline writes its output. In production, both would read from a shared
PostgreSQL incidents table rather than module-level dicts.
"""

from fastapi import APIRouter, HTTPException
from app.models.schemas import IncidentReport
from app.api.routes.alerts import _incidents

router = APIRouter()


@router.get("/", response_model=list[IncidentReport])
async def list_incidents():
    """List all generated incident reports.

    Returns incidents in arbitrary dict-insertion order. In production, you would
    add sorting (by created_at desc), pagination (limit/offset), and filtering
    (by severity, status, date range) for usability at scale.
    """
    return list(_incidents.values())


@router.get("/{incident_id}", response_model=IncidentReport)
async def get_incident(incident_id: str):
    """Get a specific incident report by its incident_id.

    Incidents are keyed by alert_id in _incidents, but exposed by incident_id.
    The linear scan here is acceptable for development. In production, maintain
    a secondary index (incident_id -> alert_id) or store in PostgreSQL with
    an index on incident_id.
    """
    incident = next(
        (i for i in _incidents.values() if i.incident_id == incident_id), None
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
