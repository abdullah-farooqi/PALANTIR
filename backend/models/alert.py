from datetime import datetime, timezone
from sqlalchemy import Column, BigInteger, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .base import Base


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    node_id = Column(Integer, ForeignKey("monitored_nodes.id", ondelete="CASCADE"), nullable=False)
    received_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    alert_name = Column(String, nullable=False)
    chart = Column(String, nullable=False)
    status = Column(String, nullable=False)  # WARNING, CRITICAL, CLEAR
    value = Column(Float, nullable=True)
    units = Column(String, nullable=True)
    triggered_agent = Column(Boolean, nullable=False, default=False)  # legacy; no longer exposed
    investigation_id = Column(Integer, nullable=True)

    node = relationship("MonitoredNode", back_populates="alert_events")
