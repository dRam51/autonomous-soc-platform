"""
FastAPI Application Entry Point

Sets up the FastAPI app, CORS middleware, and routes. This is the file that
uvicorn loads when starting the server (app.main:app).

Architecture overview:
  - FastAPI handles HTTP: request parsing, validation (via Pydantic), routing
  - Agents run as background tasks (BackgroundTasks) within FastAPI's async loop
  - Celery handles scheduled/bulk work in a separate worker process
  - All AI calls are async (AsyncAnthropic client) so the event loop is never blocked
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.routes import alerts, incidents

app = FastAPI(
    title="Autonomous SOC Platform",
    description="AI-powered Security Operations Center with multi-agent orchestration",
    version="0.1.0",
)

# CORS (Cross-Origin Resource Sharing) middleware allows the Next.js frontend
# (localhost:3000 in development) to call the FastAPI backend (localhost:8000).
# Without CORS headers, browsers block cross-origin requests. In production,
# restrict allow_origins to your actual frontend domain instead of using settings.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Route registration: each router is a module-level APIRouter with its own prefix.
# /api/v1/ versioning allows breaking changes in future versions without disrupting
# existing clients that pin to /api/v1/.
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])


@app.get("/health")
async def health_check():
    """Liveness probe used by Docker healthcheck and load balancers.

    Returns 200 with a simple payload to confirm the server is accepting requests.
    A more thorough readiness probe would also check PostgreSQL and Redis connectivity.
    """
    return {"status": "healthy", "service": "autonomous-soc-platform"}
