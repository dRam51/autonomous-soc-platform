"""
Application Settings

All configuration is read from environment variables (or a .env file in development).
Pydantic's BaseSettings validates types and raises clear errors on startup if required
variables are missing rather than failing mysteriously at runtime.

Feature flags (enable_*) let you toggle AI techniques on/off without code changes.
This is important during development: you can disable voting and self-reflection
to speed up iteration, then re-enable them before deploying to production.
"""

from pydantic_settings import BaseSettings
from typing import List
from pathlib import Path

# Resolve .env relative to this file so it works regardless of where uvicorn is launched from.
_ENV_FILE = Path(__file__).parent.parent.parent / ".env"


class Settings(BaseSettings):
    # === LLM ===
    anthropic_api_key: str

    # === Embeddings ===
    # Voyage AI is a separate service from Anthropic — get a key at voyageai.com.
    voyage_api_key: str = ""

    # === Vector Store ===
    pinecone_api_key: str
    pinecone_index_name: str = "soc-platform"

    # === Observability ===
    # LangSmith tracing: when enabled, every LangGraph node execution and LLM call
    # is recorded in LangSmith for debugging, latency analysis, and prompt comparison.
    langchain_api_key: str = ""
    langchain_tracing_v2: bool = True
    langchain_project: str = "autonomous-soc-platform"

    # === Security APIs ===
    # All three are optional (default ""): if not configured, the corresponding skill
    # returns a "not configured" message so the pipeline degrades gracefully.
    virustotal_api_key: str = ""
    nvd_api_key: str = ""       # Raises NVD rate limit from 5/30s to 50/30s
    shodan_api_key: str = ""

    # === Feature Flags ===
    # Multi-agent voting: run triage N times independently and take majority severity.
    enable_voting: bool = True
    # Self-reflection: after initial triage, a critic agent reviews and can revise it.
    enable_self_reflection: bool = True
    # Extended thinking: gives the investigation agent a reasoning scratchpad before
    # producing its final answer. More accurate but slower and more expensive.
    enable_extended_thinking: bool = True
    # Human-in-the-loop: pause pipeline on CRITICAL alerts for analyst approval.
    # Disable in development to avoid needing to manually approve every CRITICAL test alert.
    enable_hitl: bool = False
    # Anomaly filter: pre-screen alerts with Isolation Forest before the LLM pipeline.
    enable_anomaly_filter: bool = True
    # Semantic deduplication: suppress near-identical alerts within the time window.
    enable_deduplication: bool = True

    # Cosine similarity threshold for deduplication. 0.92 = very similar (almost identical).
    # Lowering to 0.85 catches more duplicates but risks suppressing distinct alerts.
    dedup_similarity_threshold: float = 0.92
    # Number of independent triage assessments to run in the voting round.
    voting_rounds: int = 3
    # Isolation Forest contamination: expected fraction of anomalous alerts (0.0-0.5).
    # 0.15 means "expect ~15% of traffic to be anomalous." Adjusting this shifts
    # the model's anomaly threshold without retraining.
    anomaly_threshold: float = 0.15

    # === Database ===
    database_url: str

    # === Redis ===
    redis_url: str = "redis://localhost:6379/0"

    # === App ===
    environment: str = "development"
    log_level: str = "INFO"
    # List of origins allowed to make cross-origin requests (for CORS middleware).
    backend_cors_origins: List[str] = ["http://localhost:3000"]

    class Config:
        env_file = _ENV_FILE
        case_sensitive = False
        extra = "ignore"  # .env has Docker-only vars (POSTGRES_USER etc.) not needed here


settings = Settings()
