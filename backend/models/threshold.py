from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Text, DateTime
from .base import Base


class SystemAlertThreshold(Base):
    __tablename__ = "system_alert_thresholds"

    id = Column(String(64), primary_key=True)  # e.g. 'cpu', 'ram', 'disk'
    name = Column(String(128), nullable=False)
    chart = Column(String(64), nullable=False)
    metric_key = Column(String(64), nullable=False)
    units = Column(String(32), nullable=False, default="%")
    warning_val = Column(Float, nullable=False)
    critical_val = Column(Float, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
