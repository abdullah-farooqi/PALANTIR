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
    capture_snapshot_created_at = Column(DateTime(timezone=True), nullable=True)
    capture_trigger_type = Column(String(16), nullable=True)
    collector_file_id = Column(String(255), nullable=True)
    file_name = Column(String(512), nullable=True)
    storage_key = Column(String(1024), nullable=True)
    size_bytes = Column(BigInteger, nullable=True)
    collector_size_bytes = Column(BigInteger, nullable=True)
    original_size_bytes = Column(BigInteger, nullable=True)
    capture_interface = Column(String(256), nullable=True)
    snaplen = Column(Integer, nullable=True)
    packet_count = Column(BigInteger, nullable=True)
    capture_started_at = Column(DateTime(timezone=True), nullable=True)
    capture_finished_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    captured_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    uploaded_at = Column(DateTime(timezone=True), nullable=True)
    upload_started_at = Column(DateTime(timezone=True), nullable=True)
    sha256 = Column(String(64), nullable=True)
    collector_sha256 = Column(String(64), nullable=True)
    hash_status = Column(String(16), nullable=True)
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
        CheckConstraint(
            "collector_size_bytes IS NULL OR collector_size_bytes >= 0",
            name="ck_investigation_evidence_collector_size_nonnegative",
        ),
        CheckConstraint(
            "original_size_bytes IS NULL OR original_size_bytes >= 0",
            name="ck_investigation_evidence_original_size_nonnegative",
        ),
        CheckConstraint(
            "packet_count IS NULL OR packet_count >= 0",
            name="ck_investigation_evidence_packet_count_nonnegative",
        ),
        CheckConstraint(
            "snaplen IS NULL OR snaplen BETWEEN 1 AND 262144",
            name="ck_investigation_evidence_snaplen",
        ),
        CheckConstraint(
            "capture_trigger_type IS NULL OR capture_trigger_type IN ('manual', 'alert', 'anomaly')",
            name="ck_investigation_evidence_trigger_type",
        ),
        CheckConstraint(
            "hash_status IS NULL OR hash_status IN ('pending', 'complete', 'unavailable', 'queue_full')",
            name="ck_investigation_evidence_hash_status",
        ),
    )
