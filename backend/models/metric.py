from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    BigInteger,
    Integer,
    String,
    DateTime,
    ForeignKey,
    PrimaryKeyConstraint,
    Float,
    Index,
)
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

    cpu_pct = Column(Float, nullable=True)
    ram_used_mb = Column(Float, nullable=True)
    ram_total_mb = Column(Float, nullable=True)
    load_avg = Column(Float, nullable=True)
    swap_used_mb = Column(Float, nullable=True)
    top_processes = Column(JSONB, nullable=True)

    __table_args__ = (
        PrimaryKeyConstraint("id", "collected_at"),
        Index("idx_snapshots_node_cat_time", "node_id", "category", "collected_at"),
        Index("idx_snapshots_cpu_pct", "cpu_pct"),
    )

    node = relationship("MonitoredNode", back_populates="snapshots")
