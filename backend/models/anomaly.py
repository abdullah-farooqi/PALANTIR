from datetime import datetime, timezone
from sqlalchemy import Column, BigInteger, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import relationship
from .base import Base


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    node_id = Column(Integer, ForeignKey("monitored_nodes.id", ondelete="CASCADE"), nullable=False)
    detected_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    contexts = Column(ARRAY(String), nullable=False)
    scores = Column(JSONB, nullable=False)
    max_score = Column(Float, nullable=False)
    triggered_agent = Column(Boolean, nullable=False, default=False)
    investigation_id = Column(Integer, nullable=True)

    node = relationship("MonitoredNode", back_populates="anomaly_events")
