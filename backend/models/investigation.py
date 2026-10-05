from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from .base import Base


class AgentInvestigation(Base):
    __tablename__ = "agent_investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_id = Column(Integer, ForeignKey("monitored_nodes.id", ondelete="CASCADE"), nullable=False)
    job_id = Column(String(64), nullable=True, unique=True)
    queued_at = Column(DateTime(timezone=True), nullable=True, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    trigger_type = Column(String, nullable=False)  # anomaly, alert, manual
    trigger_id = Column(Integer, nullable=True)     # anomaly_events.id or alert_events.id
    status = Column(String, nullable=False, default="queued")
    progress = Column(Integer, nullable=False, default=0)
    queue_delay_ms = Column(Integer, nullable=True)
    error_code = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    raw_output = Column(JSONB, nullable=True)

    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_investigation_progress"),
    )

    node = relationship("MonitoredNode", back_populates="investigations")
