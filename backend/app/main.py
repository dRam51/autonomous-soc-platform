from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.routes import alerts, incidents

app = FastAPI(
    title="Autonomous SOC Platform",
    description="AI-powered Security Operations Center with multi-agent orchestration",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "autonomous-soc-platform"}
