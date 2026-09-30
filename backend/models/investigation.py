from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from .base import Base


class AgentInvestigation(Base):
    __tablename__ = "agent_investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_id = Column(Integer, ForeignKey("monitored_nodes.id", ondelete="CASCADE"), nullable=False)
    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    trigger_type = Column(String, nullable=False)  # anomaly, alert, manual
    trigger_id = Column(Integer, nullable=True)     # anomaly_events.id or alert_events.id
    status = Column(String, nullable=False, default="running")  # running, complete, failed
    summary = Column(Text, nullable=True)
    raw_output = Column(JSONB, nullable=True)

    node = relationship("MonitoredNode", back_populates="investigations")
