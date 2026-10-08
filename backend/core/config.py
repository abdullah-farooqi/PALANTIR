from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, model_validator
from urllib.parse import urlsplit


class Settings(BaseSettings):
    PROJECT_NAME: str = "PALANTIR"
    API_V1_STR: str = "/api/v1"
    
    # Security
    PALANTIR_WEBHOOK_SECRET: str = Field(
        default="",
        description="Shared secret for /internal/alert webhook validation",
    )
    PALANTIR_API_READ_TOKEN: str = Field(
        default="",
        description="Bearer token for read-only API access; inject through the trusted proxy",
    )
    PALANTIR_API_ADMIN_TOKEN: str = Field(
        default="",
        description="Bearer token for node-management and investigation API access",
    )
    PALANTIR_API_ENROLL_TOKEN: str = Field(
        default="",
        description="Optional least-privilege token for new, create-only node enrollment",
    )
    CORS_ALLOWED_ORIGINS: str = Field(
        default="",
        description="Comma-separated explicit browser origins allowed to call the API",
    )

    @field_validator("PALANTIR_WEBHOOK_SECRET")
    @classmethod
    def validate_webhook_secret_strength(cls, value: str) -> str:
        if value and (len(value) < 32 or any(char.isspace() for char in value)):
            raise ValueError(
                "Configured webhook secrets must be at least 32 characters and contain no whitespace"
            )
        return value

    @field_validator(
        "PALANTIR_API_READ_TOKEN",
        "PALANTIR_API_ADMIN_TOKEN",
        "PALANTIR_API_ENROLL_TOKEN",
        "AGENT_AUTH_TOKEN",
    )
    @classmethod
    def validate_access_token_strength(cls, value: str) -> str:
        if value and (len(value) < 32 or any(char.isspace() for char in value)):
            raise ValueError(
                "Configured API and collector tokens must be at least 32 characters and contain no whitespace"
            )
        return value

    @model_validator(mode="after")
    def validate_secrets_are_distinct(self):
        configured = [
            token
            for token in (
                self.PALANTIR_WEBHOOK_SECRET,
                self.PALANTIR_API_READ_TOKEN,
                self.PALANTIR_API_ADMIN_TOKEN,
                self.PALANTIR_API_ENROLL_TOKEN,
                self.AGENT_AUTH_TOKEN,
            )
            if token
        ]
        if len(configured) != len(set(configured)):
            raise ValueError("Configured webhook, API, and collector tokens must be distinct")
        if self.NODE_STALE_SECONDS < self.NODE_REACHABLE_SECONDS:
            raise ValueError("NODE_STALE_SECONDS must be greater than or equal to NODE_REACHABLE_SECONDS")
        return self

    @field_validator("CORS_ALLOWED_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, value: str) -> str:
        origins = [origin.strip().rstrip("/") for origin in value.split(",") if origin.strip()]
        if "*" in origins:
            raise ValueError("CORS_ALLOWED_ORIGINS must list explicit origins, not '*'")
        for origin in origins:
            parsed = urlsplit(origin)
            try:
                valid_port = parsed.port is None or 1 <= parsed.port <= 65535
            except ValueError:
                valid_port = False
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or not valid_port
            ):
                raise ValueError(f"Invalid CORS origin: {origin}")
        return ",".join(origins)

    @property
    def cors_origins(self) -> list[str]:
        return [origin for origin in self.CORS_ALLOWED_ORIGINS.split(",") if origin]

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
    ANOMALY_THRESHOLD: float = Field(default=0.7, ge=0, le=1)
    MIN_CONTEXTS_ANOMALOUS: int = Field(default=2, ge=1)
    COOLDOWN_MINUTES: int = Field(default=10, ge=0)

    # Netdata default client timeout
    NETDATA_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=120)
    AGENT_AUTH_TOKEN: str = Field(
        default="",
        description="Optional shared token sent to PALANTIR host collector endpoints",
    )
    METRICS_RETENTION_HOURS: int = Field(default=24, ge=1)
    LOG_RETENTION_DAYS: int = Field(default=7, ge=1)
    NODE_REACHABLE_SECONDS: int = Field(default=180, ge=30)
    NODE_STALE_SECONDS: int = Field(default=900, ge=60)
    METRIC_STALE_SECONDS: int = Field(default=180, ge=60)
    WORKER_HEARTBEAT_STALE_SECONDS: int = Field(default=180, ge=60)

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
