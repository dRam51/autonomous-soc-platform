from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # LLM
    anthropic_api_key: str

    # Vector Store
    pinecone_api_key: str
    pinecone_index_name: str = "soc-platform"

    # Observability
    langchain_api_key: str = ""
    langchain_tracing_v2: bool = True
    langchain_project: str = "autonomous-soc-platform"

    # Security APIs
    virustotal_api_key: str = ""
    nvd_api_key: str = ""
    shodan_api_key: str = ""

    # Feature flags
    enable_voting: bool = True          # Multi-agent voting on triage
    enable_self_reflection: bool = True # Self-critique pass on agents
    enable_extended_thinking: bool = True  # Extended thinking on investigation
    enable_hitl: bool = False           # Human-in-the-loop (disable for dev)
    enable_anomaly_filter: bool = True  # ML pre-filter before pipeline
    enable_deduplication: bool = True   # Alert deduplication
    dedup_similarity_threshold: float = 0.92  # Cosine similarity threshold
    voting_rounds: int = 3              # Number of triage voting rounds
    anomaly_threshold: float = 0.15    # Isolation Forest contamination

    # Database
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # App
    environment: str = "development"
    log_level: str = "INFO"
    backend_cors_origins: List[str] = ["http://localhost:3000"]

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
