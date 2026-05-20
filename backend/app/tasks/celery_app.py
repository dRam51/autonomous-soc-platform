"""
Celery Application Configuration

Celery is the distributed task queue that handles long-running or scheduled
background work that should not block the FastAPI request cycle. It uses
Redis as both the message broker (task dispatch) and result backend (task status).

In this SOC platform, Celery is used for:
  - Batch API jobs (submit a batch, poll for completion, retrieve results)
  - Periodic alert clustering (run DBSCAN over the last hour of alerts)
  - Scheduled threat intel refresh (re-ingest MITRE/KEV corpus on a cron)

The FastAPI app handles real-time alert pipeline execution via BackgroundTasks
(lighter weight, no separate worker process). Celery handles heavier, async,
or scheduled work that can tolerate more latency and needs durability across restarts.
"""

from celery import Celery
from app.config import settings

celery_app = Celery(
    "soc_platform",
    # Redis as broker: FastAPI publishes task messages to a Redis queue;
    # Celery workers consume them. This decouples producers from consumers
    # and allows horizontal scaling by adding more workers.
    broker=settings.redis_url,
    # Redis as result backend: task return values and status are stored here
    # so callers can poll for completion or retrieve results by task_id.
    backend=settings.redis_url,
    # Include tells Celery where to find task definitions to auto-discover them.
    include=["app.tasks.pipeline"],
)

celery_app.conf.update(
    # JSON serialization is used over pickle for security: pickle can execute
    # arbitrary code on deserialization, which is a risk in a multi-tenant system.
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # task_track_started=True means a task transitions to STARTED state when a worker
    # picks it up. Without this, tasks jump from PENDING to SUCCESS/FAILURE with no
    # intermediate state, making it hard to detect hung workers.
    task_track_started=True,
)
