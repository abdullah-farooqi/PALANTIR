from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    PrimaryKeyConstraint,
    String,
    CheckConstraint,
)
from .base import Base


class CategoryCollectionStatus(Base):
    __tablename__ = "node_category_collection_status"

    node_id = Column(
        Integer,
        ForeignKey("monitored_nodes.id", ondelete="CASCADE"),
        nullable=False,
    )
    category = Column(String(32), nullable=False)
    source = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    error_code = Column(String(64), nullable=True)
    error_message = Column(String(300), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        PrimaryKeyConstraint("node_id", "category", "source"),
        CheckConstraint(
            "category IN ('system','storage','network','services','processes','connections','containers','vms')",
            name="ck_node_category_status_category",
        ),
        CheckConstraint(
            "source IN ('netdata','palantir-agent')",
            name="ck_node_category_status_source",
        ),
        CheckConstraint(
            "status IN ('unknown','available','not_configured','unsupported','collection_error')",
            name="ck_node_category_status_status",
        ),
    )
