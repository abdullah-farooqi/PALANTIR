from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String
from .base import Base


class ServiceHeartbeat(Base):
    __tablename__ = "service_heartbeats"

    name = Column(String(64), primary_key=True)
    last_started_at = Column(DateTime(timezone=True), nullable=True)
    last_completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(16), nullable=False, default="unknown")
    error_code = Column(String(64), nullable=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    last_duration_ms = Column(Integer, nullable=True)
    run_count = Column(Integer, nullable=False, default=0)
    failure_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
