from datetime import datetime, timezone

from sqlalchemy import BigInteger, CheckConstraint, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint

from .base import Base


class InvestigationEvidence(Base):
    """One transferred PCAP artifact, or a failed/unavailable capture attempt."""

    __tablename__ = "investigation_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(
        Integer,
        ForeignKey("agent_investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_event_id = Column(
        BigInteger,
        ForeignKey("alert_events.id", ondelete="SET NULL"),
        nullable=True,
    )
    node_id = Column(
        Integer,
        ForeignKey("monitored_nodes.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_type = Column(String(50), nullable=False, default="pcap_collection")
    capture_snapshot_id = Column(String(32), nullable=True)
    collector_file_id = Column(String(255), nullable=True)
    file_name = Column(String(512), nullable=True)
    storage_key = Column(String(1024), nullable=True)
    size_bytes = Column(BigInteger, nullable=True)
    original_size_bytes = Column(BigInteger, nullable=True)
    capture_started_at = Column(DateTime(timezone=True), nullable=True)
    capture_finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    captured_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    uploaded_at = Column(DateTime(timezone=True), nullable=True)
    upload_started_at = Column(DateTime(timezone=True), nullable=True)
    sha256 = Column(String(64), nullable=True)
    compression = Column(String(16), nullable=True)
    status = Column(String(16), nullable=False, default="queued")
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("investigation_id", "collector_file_id", name="uq_inv_evidence_collector_file"),
        CheckConstraint(
            "status IN ('queued', 'uploading', 'complete', 'failed', 'unavailable')",
            name="ck_investigation_evidence_status",
        ),
        CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_investigation_evidence_size_nonnegative",
        ),
    )
