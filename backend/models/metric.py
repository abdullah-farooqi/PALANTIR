from datetime import datetime, timezone
from sqlalchemy import Column, BigInteger, Integer, String, DateTime, ForeignKey, PrimaryKeyConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from .base import Base


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id = Column(BigInteger, autoincrement=True)
    node_id = Column(Integer, ForeignKey("monitored_nodes.id", ondelete="CASCADE"), nullable=False)
    collected_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    category = Column(String, nullable=False)
    data = Column(JSONB, nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint("id", "collected_at"),
    )

    node = relationship("MonitoredNode", back_populates="snapshots")
