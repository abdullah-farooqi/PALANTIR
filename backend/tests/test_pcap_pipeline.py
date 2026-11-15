"""Unit and integration tests for PCAP analysis pipeline (Milestone 1)."""

import gzip
import socket
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from core.config import settings
from core.database import get_sync_session
from models.investigation import AgentInvestigation
from models.investigation_evidence import InvestigationEvidence
from models.node import MonitoredNode
from models.pcap_analysis import PcapAnalysisRuns, PcapFlows
from workers.pcap_pipeline import (
    _read_pure_python_packets,
    normalize_flow_key,
    open_decompressed_pcap,
    pcap_analysis_extract_flows,
    pcap_analysis_validate,
    start_pcap_analysis,
)


def build_synthetic_pcap_bytes(snaplen: int = 65535) -> bytes:
    """Construct a valid classic PCAP byte buffer with forward and reverse TCP packets and UDP."""
    # Global Header (24 bytes)
    magic = b"\xd4\xc3\xb2\xa1"  # Little-endian microseconds
    gh = magic + struct.pack("<HHiIII", 2, 4, 0, 0, snaplen, 1)  # Linktype 1 = Ethernet

    packets = []
    base_ts = 1700000000

    # 1. TCP SYN: 192.168.1.50:45000 -> 10.0.0.1:80
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    ip1 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 101, 0x4000, 64, 6, 0,
        socket.inet_aton("192.168.1.50"), socket.inet_aton("10.0.0.1"),
    )
    tcp1 = struct.pack("!HHIIBBHHH", 45000, 80, 1000, 0, (5 << 4), 0x02, 65535, 0, 0)
    pkt1 = eth + ip1 + tcp1
    hdr1 = struct.pack("<IIII", base_ts, 100000, len(pkt1), len(pkt1))
    packets.append(hdr1 + pkt1)

    # 2. TCP SYN-ACK: 10.0.0.1:80 -> 192.168.1.50:45000 (Reverse)
    ip2 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 201, 0x4000, 64, 6, 0,
        socket.inet_aton("10.0.0.1"), socket.inet_aton("192.168.1.50"),
    )
    tcp2 = struct.pack("!HHIIBBHHH", 80, 45000, 5000, 1001, (5 << 4), 0x12, 65535, 0, 0)
    pkt2 = eth + ip2 + tcp2
    hdr2 = struct.pack("<IIII", base_ts + 1, 200000, len(pkt2), len(pkt2))
    packets.append(hdr2 + pkt2)

    # 3. TCP ACK: 192.168.1.50:45000 -> 10.0.0.1:80 (Forward)
    tcp3 = struct.pack("!HHIIBBHHH", 45000, 80, 1001, 5001, (5 << 4), 0x10, 65535, 0, 0)
    pkt3 = eth + ip1 + tcp3
    hdr3 = struct.pack("<IIII", base_ts + 2, 300000, len(pkt3), len(pkt3))
    packets.append(hdr3 + pkt3)

    # 4. UDP packet: 192.168.1.50:53000 -> 8.8.8.8:53 (DNS)
    ip4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 36, 301, 0, 64, 17, 0,
        socket.inet_aton("192.168.1.50"), socket.inet_aton("8.8.8.8"),
    )
    udp4 = struct.pack("!HHHH", 53000, 53, 16, 0) + b"DNS_TEST"
    pkt4 = eth + ip4 + udp4
    hdr4 = struct.pack("<IIII", base_ts + 3, 400000, len(pkt4), len(pkt4))
    packets.append(hdr4 + pkt4)

    return gh + b"".join(packets)


def test_flow_key_normalization():
    """Verify bidirectional normalization of 5-tuples."""
    k1, is_fwd1 = normalize_flow_key("192.168.1.50", "10.0.0.1", 45000, 80, "tcp")
    k2, is_fwd2 = normalize_flow_key("10.0.0.1", "192.168.1.50", 80, 45000, "tcp")
    assert k1 == k2
    assert is_fwd1 != is_fwd2


def test_pure_python_parser_extracts_packets(tmp_path):
    """Verify native PCAP reader extracts 5-tuple and flag metadata."""
    pcap_data = build_synthetic_pcap_bytes()
    pcap_file = tmp_path / "synthetic.pcap"
    pcap_file.write_bytes(pcap_data)

    packets = list(_read_pure_python_packets(pcap_file))
    assert len(packets) == 4

    p1, p2, p3, p4 = packets
    assert p1["protocol"] == "tcp"
    assert p1["src_ip"] == "192.168.1.50"
    assert p1["dst_ip"] == "10.0.0.1"
    assert p1["src_port"] == 45000
    assert p1["dst_port"] == 80
    assert p1["flags"]["SYN"] == 1
    assert p1["flags"]["ACK"] == 0

    assert p2["protocol"] == "tcp"
    assert p2["src_ip"] == "10.0.0.1"
    assert p2["dst_ip"] == "192.168.1.50"
    assert p2["flags"]["SYN"] == 1
    assert p2["flags"]["ACK"] == 1

    assert p4["protocol"] == "udp"
    assert p4["src_port"] == 53000
    assert p4["dst_port"] == 53


def test_open_decompressed_pcap_gzip(tmp_path):
    """Verify gzip compressed captures are decompressed via open_decompressed_pcap."""
    raw_bytes = build_synthetic_pcap_bytes()
    gz_file = tmp_path / "capture.pcap.gz"
    with gzip.open(gz_file, "wb") as gz_out:
        gz_out.write(raw_bytes)

    with open_decompressed_pcap(gz_file) as decompressed:
        assert decompressed.is_file()
        assert decompressed.read_bytes() == raw_bytes


def test_pcap_validation_valid(tmp_path, monkeypatch):
    """Validate a properly formatted PCAP evidence file."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    node_dir = tmp_path / "1" / "1"
    node_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = node_dir / "evidence-1.pcap"
    pcap_path.write_bytes(build_synthetic_pcap_bytes(snaplen=2048))

    with get_sync_session() as session:
        # Create test node
        node = MonitoredNode(hostname="test-node-pipeline", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()

        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()

        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="evidence-1.pcap",
            storage_key="1/1/evidence-1.pcap",
            status="complete",
        )
        session.add(ev)
        session.flush()

        run_id = uuid4().hex
        run = PcapAnalysisRuns(
            run_id=run_id,
            evidence_id=ev.id,
            investigation_id=inv.id,
            node_id=node.id,
            status="pending",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_validate(evidence_id=ev_id, run_id=run_id)
    assert res["status"] == "valid"
    assert res["packet_count"] == 4
    assert res["payload_available"] is True
    assert res["snaplen"] == 2048


def test_pcap_validation_corrupted_fails(tmp_path, monkeypatch):
    """Corrupted PCAP should fail validation and mark run as failed."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    corrupted = tmp_path / "corrupt.pcap"
    corrupted.write_bytes(b"invalid_pcap_content_shorter_than_24")

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-corrupt", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="corrupt.pcap",
            storage_key="corrupt.pcap",
            status="complete",
        )
        session.add(ev)
        session.flush()
        run_id = uuid4().hex
        run = PcapAnalysisRuns(
            run_id=run_id,
            evidence_id=ev.id,
            investigation_id=inv.id,
            node_id=node.id,
            status="pending",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    with pytest.raises(Exception):
        pcap_analysis_validate(evidence_id=ev_id, run_id=run_id)

    with get_sync_session() as session:
        updated_run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one()
        assert updated_run.status == "failed"
        assert updated_run.error_step == "validate"


def test_flow_extraction_persists_flows(tmp_path, monkeypatch):
    """Extract flows from synthetic PCAP and verify bidirectional flow tracking."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    pcap_path = tmp_path / "flows.pcap"
    pcap_path.write_bytes(build_synthetic_pcap_bytes())

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-flows", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="flows.pcap",
            storage_key="flows.pcap",
            status="complete",
        )
        session.add(ev)
        session.flush()
        run_id = uuid4().hex
        run = PcapAnalysisRuns(
            run_id=run_id,
            evidence_id=ev.id,
            investigation_id=inv.id,
            node_id=node.id,
            status="running",
            current_step="validate",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_extract_flows(ev_id, run_id=run_id)
    assert res["status"] == "complete"
    assert res["flow_count"] == 2  # 1 TCP bidirectional flow + 1 UDP flow

    with get_sync_session() as session:
        flows = session.execute(
            select(PcapFlows).where(PcapFlows.run_id == run_id)
        ).scalars().all()
        assert len(flows) == 2

        tcp_flow = next(f for f in flows if f.protocol == "tcp")
        assert tcp_flow.bidirectional is True
        assert tcp_flow.packet_count + tcp_flow.reverse_packet_count == 3
        assert tcp_flow.flags["SYN"] == 2
        assert tcp_flow.flags["ACK"] == 2

        udp_flow = next(f for f in flows if f.protocol == "udp")
        assert udp_flow.bidirectional is False
        assert udp_flow.packet_count + udp_flow.reverse_packet_count == 1


def test_start_pcap_analysis_enqueues_chain(tmp_path, monkeypatch):
    """start_pcap_analysis creates a pending PcapAnalysisRuns record and returns run_id."""
    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-chain", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        inv_id = inv.id
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="chain.pcap",
            storage_key="chain.pcap",
            status="complete",
        )
        session.add(ev)
        session.commit()
        ev_id = ev.id

    run_id = start_pcap_analysis(ev_id)
    assert isinstance(run_id, str)
    assert len(run_id) == 32

    with get_sync_session() as session:
        run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one()
        assert run.status == "pending"
        assert run.evidence_id == ev_id
        assert run.investigation_id == inv_id
