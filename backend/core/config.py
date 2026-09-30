from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_NAME: str = "PALANTIR"
    API_V1_STR: str = "/api/v1"
    
    # Security
    PALANTIR_WEBHOOK_SECRET: str = Field(
        default="palantir-super-secret-key-change-me",
        description="Shared secret for /internal/alert webhook validation",
    )

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://palantir:palantir@localhost:5432/palantir",
        description="Async PostgreSQL database URL",
    )
    SYNC_DATABASE_URL: str = Field(
        default="postgresql+psycopg://palantir:palantir@localhost:5432/palantir",
        description="Sync PostgreSQL URL for Celery workers",
    )

    # Redis & Celery
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL for broker and caching",
    )

    # Anomaly Engine Config
    ANOMALY_THRESHOLD: float = 0.7
    MIN_CONTEXTS_ANOMALOUS: int = 2
    COOLDOWN_MINUTES: int = 10

    # Netdata default client timeout
    NETDATA_TIMEOUT_SECONDS: float = 5.0

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
