from datetime import datetime, timezone

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from .base import Base


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    node_id = Column(Integer, ForeignKey("monitored_nodes.id", ondelete="CASCADE"), nullable=False)
    event_id = Column(String(64), nullable=False)
    event_at = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    source = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, default="unknown")
    service = Column(String(255), nullable=True)
    pid = Column(Integer, nullable=True)
    message = Column(Text, nullable=False)
    fields = Column(JSONB, nullable=False, default=dict)
    parser = Column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("node_id", "event_id", name="uq_log_events_node_event"),
        Index("idx_log_events_node_time", "node_id", "event_at"),
        Index("idx_log_events_node_severity_time", "node_id", "severity", "event_at"),
    )

    node = relationship("MonitoredNode", backref="log_events")
