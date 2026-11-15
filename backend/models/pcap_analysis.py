from datetime import datetime, timezone
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import relationship

from .base import Base


class PcapAnalysisRuns(Base):
    """Execution tracking for automated PCAP analysis pipelines."""

    __tablename__ = "pcap_analysis_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), unique=True, nullable=False, index=True)
    evidence_id = Column(
        Integer,
        ForeignKey("investigation_evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_id = Column(
        Integer,
        ForeignKey("agent_investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_id = Column(
        Integer,
        ForeignKey("monitored_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status = Column(
        String(16),
        nullable=False,
        default="pending",
    )
    current_step = Column(String(64), nullable=True)
    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    error_step = Column(String(64), nullable=True)
    rollback_started_at = Column(DateTime(timezone=True), nullable=True)
    rollback_completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'complete', 'failed', 'rolled_back')",
            name="ck_pcap_analysis_runs_status",
        ),
        CheckConstraint(
            "evidence_id IS NOT NULL AND investigation_id IS NOT NULL",
            name="ck_pcap_analysis_runs_evidence_inv",
        ),
        Index("idx_pcap_runs_status", "status"),
    )

    evidence = relationship("InvestigationEvidence", foreign_keys=[evidence_id])
    investigation = relationship("AgentInvestigation", foreign_keys=[investigation_id])
    node = relationship("MonitoredNode", foreign_keys=[node_id])
    flows = relationship("PcapFlows", back_populates="run", cascade="all, delete-orphan")


class PcapFlows(Base):
    """Bidirectional 5-tuple network flows derived from raw packet captures."""

    __tablename__ = "pcap_flows"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    run_id = Column(
        String(64),
        ForeignKey("pcap_analysis_runs.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_id = Column(
        Integer,
        ForeignKey("investigation_evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # 5-tuple
    src_ip = Column(INET, nullable=False, index=True)
    dst_ip = Column(INET, nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(8), nullable=False, index=True)

    # Bidirectional normalized key
    flow_key = Column(String(128), nullable=False, index=True)

    # Flow statistics
    packet_count = Column(Integer, nullable=False, default=0)
    byte_count = Column(BigInteger, nullable=False, default=0)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    duration_seconds = Column(Float, nullable=True)

    # Direction tracking
    bidirectional = Column(Boolean, nullable=False, default=False)
    reverse_packet_count = Column(Integer, nullable=False, default=0)
    reverse_byte_count = Column(BigInteger, nullable=False, default=0)

    # Protocol metadata
    flags = Column(JSONB, nullable=True)
    dscp = Column(Integer, nullable=True)
    fragment_count = Column(Integer, nullable=False, default=0)

    captured_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint("run_id", "flow_key", name="uq_pcap_flows_run_key"),
        CheckConstraint(
            "protocol IN ('tcp', 'udp', 'icmp', 'icmpv6')",
            name="ck_pcap_flows_protocol",
        ),
        CheckConstraint(
            "src_port IS NULL OR (src_port >= 0 AND src_port <= 65535)",
            name="ck_pcap_flows_src_port",
        ),
        CheckConstraint(
            "dst_port IS NULL OR (dst_port >= 0 AND dst_port <= 65535)",
            name="ck_pcap_flows_dst_port",
        ),
        CheckConstraint(
            "duration_seconds IS NULL OR duration_seconds >= 0",
            name="ck_pcap_flows_duration",
        ),
        CheckConstraint("packet_count >= 0", name="ck_pcap_flows_packet_count"),
        CheckConstraint("byte_count >= 0", name="ck_pcap_flows_byte_count"),
        Index("idx_pcap_flows_time", "first_seen", "last_seen"),
    )

    run = relationship("PcapAnalysisRuns", back_populates="flows")
    evidence = relationship("InvestigationEvidence", foreign_keys=[evidence_id])
