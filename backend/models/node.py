from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from .base import Base


class MonitoredNode(Base):
    __tablename__ = "monitored_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String, nullable=False, unique=True)
    netdata_url = Column(String, nullable=False)
    collector_url = Column(String, nullable=True)
    capabilities = Column(JSONB, nullable=True)
    os_type = Column(String, nullable=False, default="linux")
    active = Column(Boolean, nullable=False, default=True)
    context_count = Column(Integer, nullable=True)
    alert_count = Column(Integer, nullable=True)
    registered_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_collection_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    snapshots = relationship("MetricSnapshot", back_populates="node", cascade="all, delete-orphan")
    anomaly_events = relationship("AnomalyEvent", back_populates="node", cascade="all, delete-orphan")
    alert_events = relationship("AlertEvent", back_populates="node", cascade="all, delete-orphan")
    investigations = relationship("AgentInvestigation", back_populates="node", cascade="all, delete-orphan")
