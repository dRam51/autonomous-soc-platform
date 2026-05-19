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
