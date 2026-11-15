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
    sessions = relationship("TcpSessions", back_populates="run", cascade="all, delete-orphan")
    artifacts = relationship("PcapArtifacts", back_populates="run", cascade="all, delete-orphan")
    iocs = relationship("PcapIocs", back_populates="run", cascade="all, delete-orphan")


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
    artifacts = relationship("PcapArtifacts", back_populates="flow")


class TcpSessions(Base):
    """Reconstructed TCP session tracking sequence metrics, quality, and reassembly state."""

    __tablename__ = "tcp_sessions"

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

    src_ip = Column(INET, nullable=False)
    dst_ip = Column(INET, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)

    state = Column(
        String(16),
        nullable=False,
        default="open",
        index=True,
    )

    server_isn = Column(BigInteger, nullable=True)
    client_isn = Column(BigInteger, nullable=True)
    server_win_size = Column(Integer, nullable=True)
    client_win_size = Column(Integer, nullable=True)

    total_bytes = Column(BigInteger, nullable=False, default=0)
    reassembled_bytes = Column(BigInteger, nullable=False, default=0)
    missing_bytes = Column(BigInteger, nullable=False, default=0)
    retransmit_bytes = Column(BigInteger, nullable=False, default=0)
    ooo_bytes = Column(BigInteger, nullable=False, default=0)
    overlap_bytes = Column(BigInteger, nullable=False, default=0)
    reassembly_quality = Column(Float, nullable=True, index=True)

    syn_time = Column(DateTime(timezone=True), nullable=True)
    established_time = Column(DateTime(timezone=True), nullable=True)
    close_time = Column(DateTime(timezone=True), nullable=True)
    last_activity = Column(DateTime(timezone=True), nullable=True)

    snaplen = Column(Integer, nullable=False)
    payload_truncated = Column(Boolean, nullable=False, default=False)
    confidence = Column(
        String(8),
        nullable=False,
        default="high",
        index=True,
    )

    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    duration_seconds = Column(Float, nullable=True)

    captured_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint("run_id", "src_ip", "dst_ip", "src_port", "dst_port", "first_seen", name="uq_tcp_sessions_run_flow"),
        CheckConstraint(
            "state IN ('open', 'established', 'closed', 'reset', 'half_open', 'incomplete')",
            name="ck_tcp_sessions_state",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_tcp_sessions_confidence",
        ),
        CheckConstraint(
            "src_port >= 0 AND src_port <= 65535",
            name="ck_tcp_sessions_src_port",
        ),
        CheckConstraint(
            "dst_port >= 0 AND dst_port <= 65535",
            name="ck_tcp_sessions_dst_port",
        ),
    )

    run = relationship("PcapAnalysisRuns", back_populates="sessions")
    evidence = relationship("InvestigationEvidence", foreign_keys=[evidence_id])
    artifacts = relationship("PcapArtifacts", back_populates="session")


class PcapArtifacts(Base):
    """Forensic payload artifacts extracted from streams (HTTP, DNS, TLS metadata)."""

    __tablename__ = "pcap_artifacts"

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

    artifact_type = Column(
        String(32),
        nullable=False,
        index=True,
    )
    session_id = Column(
        BigInteger,
        ForeignKey("tcp_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    flow_id = Column(
        BigInteger,
        ForeignKey("pcap_flows.id", ondelete="SET NULL"),
        nullable=True,
    )

    content_type = Column(String(255), nullable=True)
    content_length = Column(BigInteger, nullable=True)
    sha256 = Column(String(64), nullable=True, index=True)
    storage_key = Column(String(1024), nullable=True)
    storage_prefix = Column(String(255), nullable=True, index=True)

    metadata_json = Column("metadata", JSONB, nullable=False, default=dict)
    size_bytes = Column(BigInteger, nullable=False, default=0)
    max_size_exceeded = Column(Boolean, nullable=False, default=False)

    captured_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        CheckConstraint(
            "artifact_type IN ('http_request', 'http_response', 'dns_query', 'dns_response', 'tls_client_hello', 'tls_server_hello', 'tls_certificate', 'tls_ja3')",
            name="ck_pcap_artifacts_type",
        ),
        CheckConstraint(
            "size_bytes >= 0",
            name="ck_pcap_artifacts_size_bytes",
        ),
        CheckConstraint(
            "storage_key IS NULL OR sha256 IS NOT NULL",
            name="ck_pcap_artifacts_storage",
        ),
    )

    run = relationship("PcapAnalysisRuns", back_populates="artifacts")
    evidence = relationship("InvestigationEvidence", foreign_keys=[evidence_id])
    session = relationship("TcpSessions", back_populates="artifacts")
    flow = relationship("PcapFlows", back_populates="artifacts")


class PcapIocAllowlist(Base):
    """Allowlist patterns for suppressing benign IOCs during PCAP analysis."""

    __tablename__ = "pcap_ioc_allowlist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(32), nullable=False)
    pattern = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("idx_pcap_ioc_allowlist_uniq", "ioc_type", "pattern", unique=True),
    )


class PcapIocs(Base):
    """Indicators of Compromise extracted from network flows and forensic artifacts."""

    __tablename__ = "pcap_iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
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

    ioc_type = Column(String(32), nullable=False)  # ipv4, ipv6, domain, url, sha256, ja3, port
    ioc_value = Column(String(512), nullable=False)
    context = Column(JSONB, nullable=False, default=dict)
    is_allowlisted = Column(Boolean, nullable=False, default=False, index=True)
    threat_intel_match = Column(JSONB, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("idx_pcap_iocs_type_val", "ioc_type", "ioc_value"),
    )

    run = relationship("PcapAnalysisRuns", back_populates="iocs")
    evidence = relationship("InvestigationEvidence", foreign_keys=[evidence_id])

