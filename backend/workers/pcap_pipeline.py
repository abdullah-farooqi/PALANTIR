"""PCAP Forensic Analysis Pipeline: validation, flow extraction, and session processing."""

from __future__ import annotations

import contextlib
import gzip
import ipaddress
import logging
import os
import shutil
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Iterator
from uuid import uuid4

try:
    from celery import chain, shared_task
except ImportError:
    class chain:  # type: ignore
        def __init__(self, *tasks):
            self.tasks = tasks
        def apply_async(self, *args, **kwargs):
            return None

    def shared_task(*args, **kwargs):
        def decorator(fn):
            fn.delay = fn
            fn.apply_async = lambda *a, **k: fn(*a, **k)
            fn.s = lambda *a, **k: fn
            fn.si = lambda *a, **k: fn
            return fn
        return decorator
from sqlalchemy import select

from core.config import settings
from core.database import get_sync_session
from core.storage import get_storage_backend
from models.investigation_evidence import InvestigationEvidence
from models.pcap_analysis import PcapAnalysisRuns, PcapArtifacts, PcapFlows, TcpSessions
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# Scapy import with fallback
try:
    from scapy.all import (
        DNS,
        Dot1Q,
        Ether,
        ICMP,
        IP,
        IPv6,
        PcapReader,
        Raw,
        TCP,
        UDP,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Helper: Decompression context manager (raw, gzip, zstd)
# ─────────────────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def open_decompressed_pcap(path: Path) -> Generator[Path, None, None]:
    """Yield a local uncompressed PCAP Path, decompressing zstd or gzip if needed."""
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"PCAP file not found: {resolved}")

    suffix = resolved.suffix.lower()
    if suffix not in {".zst", ".gz"}:
        yield resolved
        return

    # Create temporary file for decompressed capture
    fd, temp_path_str = tempfile.mkstemp(prefix="palantir_pcap_", suffix=".pcap")
    os.close(fd)
    temp_path = Path(temp_path_str)

    try:
        if suffix == ".gz":
            with gzip.open(resolved, "rb") as src, temp_path.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
        elif suffix == ".zst":
            decompressed = False
            try:
                import zstandard as zstd
                dctx = zstd.ZstdDecompressor()
                with resolved.open("rb") as src, temp_path.open("wb") as dst:
                    dctx.copy_stream(src, dst)
                decompressed = True
            except (ImportError, Exception) as zerr:
                logger.debug("zstandard library decompression failed (%s), trying zstd CLI", zerr)

            if not decompressed:
                if shutil.which("zstd") is not None:
                    res = subprocess.run(
                        ["zstd", "-d", "-q", "-c", str(resolved)],
                        stdout=temp_path.open("wb"),
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    if res.returncode != 0:
                        raise RuntimeError(f"zstd command line decompress failed with exit code {res.returncode}")
                else:
                    raise RuntimeError("zstd decompression required but neither zstandard nor zstd CLI is available")

        yield temp_path
    finally:
        temp_path.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Resilient Pure-Python PCAP Stream Parser (fallback / fast inspection)
# ─────────────────────────────────────────────────────────────────────────────

def _read_pure_python_packets(path: Path) -> Iterator[dict[str, Any]]:
    """Stream Ethernet / IP / TCP / UDP packets directly using struct packing.
    Handles classic PCAP format across both endian encodings.
    """
    with path.open("rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return

        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),      # Microseconds, little-endian
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000),      # Microseconds, big-endian
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # Nanoseconds, little-endian
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # Nanoseconds, big-endian
        }
        enc = formats.get(magic)
        if not enc:
            return

        endian, fraction_scale = enc
        _v_major, _v_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(f"{endian}HHiIII", header[4:24])
        pkt_hdr = struct.Struct(f"{endian}IIII")

        while True:
            hdr_bytes = f.read(16)
            if len(hdr_bytes) < 16:
                break
            sec, frac, caplen, origlen = pkt_hdr.unpack(hdr_bytes)
            data = f.read(caplen)
            if len(data) < caplen:
                break

            ts = datetime.fromtimestamp(sec + (frac / fraction_scale), timezone.utc)
            parsed = _parse_packet_bytes(data, linktype, ts, origlen)
            if parsed is not None:
                parsed["snaplen"] = snaplen
                yield parsed


def _parse_packet_bytes(data: bytes, linktype: int, timestamp: datetime, orig_len: int) -> dict[str, Any] | None:
    """Parse raw bytes into a packet dictionary containing 5-tuple and metadata."""
    offset = 0
    # Linktype 1 is Ethernet (EN10MB), Linktype 12/101 is Raw IP
    if linktype == 1:
        if len(data) < 14:
            return None
        eth_type = struct.unpack("!H", data[12:14])[0]
        offset = 14
        if eth_type == 0x8100:  # 802.1Q VLAN
            if len(data) < 18:
                return None
            eth_type = struct.unpack("!H", data[16:18])[0]
            offset = 18
    elif linktype in (12, 101):
        eth_type = 0x0800 if (data[0] >> 4) == 4 else 0x86DD
    else:
        return None

    proto = None
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    dscp = None
    fragment_count = 0
    flags: dict[str, int] = {}
    seq = 0
    ack = 0
    win = 0
    payload = b""

    if eth_type == 0x0800:  # IPv4
        if len(data) < offset + 20:
            return None
        v_ihl, tos, total_len, _id, flags_offset, ttl, proto_num, _csum = struct.unpack("!BBHHHBBH", data[offset:offset + 12])
        ihl = (v_ihl & 0x0F) * 4
        dscp = (tos >> 2) & 0x3F
        frag_offset = flags_offset & 0x1FFF
        more_frags = bool(flags_offset & 0x2000)
        if frag_offset > 0 or more_frags:
            fragment_count = 1

        src_ip = str(ipaddress.IPv4Address(data[offset + 12:offset + 16]))
        dst_ip = str(ipaddress.IPv4Address(data[offset + 16:offset + 20]))
        l4_offset = offset + ihl
    elif eth_type == 0x86DD:  # IPv6
        if len(data) < offset + 40:
            return None
        vtc_fl, payload_len, next_hdr, _hop_limit = struct.unpack("!IHBB", data[offset:offset + 8])
        dscp = (vtc_fl >> 22) & 0x3F
        src_ip = str(ipaddress.IPv6Address(data[offset + 8:offset + 24]))
        dst_ip = str(ipaddress.IPv6Address(data[offset + 24:offset + 40]))
        proto_num = next_hdr
        l4_offset = offset + 40
    else:
        return None

    if proto_num == 6:  # TCP
        proto = "tcp"
        if len(data) >= l4_offset + 20:
            src_port, dst_port, seq, ack, data_offset_flags, win = struct.unpack("!HHIIHH", data[l4_offset:l4_offset + 16])
            tcp_header_len = max(20, ((data_offset_flags >> 12) & 0x0F) * 4)
            tcp_flags = data_offset_flags & 0x01FF
            flags = {
                "FIN": 1 if tcp_flags & 0x01 else 0,
                "SYN": 1 if tcp_flags & 0x02 else 0,
                "RST": 1 if tcp_flags & 0x04 else 0,
                "PSH": 1 if tcp_flags & 0x08 else 0,
                "ACK": 1 if tcp_flags & 0x10 else 0,
                "URG": 1 if tcp_flags & 0x20 else 0,
            }
            if len(data) > l4_offset + tcp_header_len:
                payload = data[l4_offset + tcp_header_len:]
    elif proto_num == 17:  # UDP
        proto = "udp"
        if len(data) >= l4_offset + 8:
            src_port, dst_port, udp_len = struct.unpack("!HHH", data[l4_offset:l4_offset + 6])
            payload = data[l4_offset + 8:]
    elif proto_num == 1:  # ICMP
        proto = "icmp"
    elif proto_num == 58:  # ICMPv6
        proto = "icmpv6"
    else:
        return None

    return {
        "timestamp": timestamp,
        "length": orig_len,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "dscp": dscp,
        "fragment_count": fragment_count,
        "flags": flags,
        "seq": seq,
        "ack": ack,
        "win": win,
        "payload": payload,
    }


def normalize_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
) -> tuple[str, bool]:
    """Compute deterministic bidirectional flow key and direction indicator.
    Returns (flow_key, is_forward).
    """
    port_a = src_port if src_port is not None else 0
    port_b = dst_port if dst_port is not None else 0
    endpoint_a = (src_ip, port_a)
    endpoint_b = (dst_ip, port_b)

    if endpoint_a <= endpoint_b:
        return f"{protocol}:{src_ip}:{port_a}-{dst_ip}:{port_b}", True
    return f"{protocol}:{dst_ip}:{port_b}-{src_ip}:{port_a}", False


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: PCAP Validation Task
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="workers.pcap_pipeline.pcap_analysis_validate")
def pcap_analysis_validate(self, evidence_id: int, run_id: str) -> dict[str, Any]:
    """Validate PCAP file structure, extract capture bounds and link properties."""
    logger.info("Validating PCAP evidence %s for run %s", evidence_id, run_id)

    with get_sync_session() as session:
        run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one_or_none()
        if run is None:
            raise ValueError(f"Analysis run {run_id} not found in database")

        run.status = "running"
        run.current_step = "validate"
        session.commit()

        evidence = session.execute(
            select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id)
        ).scalar_one_or_none()
        if evidence is None or not evidence.storage_key:
            run.status = "failed"
            run.error_step = "validate"
            run.error_message = "Stored PCAP evidence record or storage reference is unavailable."
            session.commit()
            raise FileNotFoundError(run.error_message)

        pcap_path = settings.PCAP_STORAGE_DIR / evidence.storage_key

    if not pcap_path.is_file():
        with get_sync_session() as session:
            run = session.execute(
                select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
            ).scalar_one()
            run.status = "failed"
            run.error_step = "validate"
            run.error_message = f"Evidence capture file is missing from disk: {pcap_path.name}"
            session.commit()
        raise FileNotFoundError(f"File missing on master storage: {pcap_path}")

    packet_count = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    snaplen = 128
    link_type = "Ethernet"

    try:
        with open_decompressed_pcap(pcap_path) as decompressed_file:
            file_size = decompressed_file.stat().st_size
            if file_size < 24:
                raise ValueError("PCAP file is smaller than minimum 24-byte header size")

            # Validate header using Scapy if present, else fallback
            if SCAPY_AVAILABLE:
                try:
                    with PcapReader(str(decompressed_file)) as reader:
                        # Scapy exposes snaplen / linktype on the reader object
                        snaplen = getattr(reader, "snaplen", 128)
                        for pkt in reader:
                            packet_count += 1
                            ts = datetime.fromtimestamp(float(pkt.time), timezone.utc)
                            if first_seen is None or ts < first_seen:
                                first_seen = ts
                            if last_seen is None or ts > last_seen:
                                last_seen = ts
                            if packet_count >= 500_000:
                                # Cap validation loop on massive files
                                break
                except Exception as scapy_err:
                    logger.debug("Scapy reader failed validation (%s), falling back to native parser", scapy_err)
                    packet_count = 0
                    first_seen = None
                    last_seen = None

            if packet_count == 0:
                for pkt_info in _read_pure_python_packets(decompressed_file):
                    packet_count += 1
                    ts = pkt_info["timestamp"]
                    snaplen = pkt_info.get("snaplen", snaplen)
                    if first_seen is None or ts < first_seen:
                        first_seen = ts
                    if last_seen is None or ts > last_seen:
                        last_seen = ts

        if packet_count == 0:
            raise ValueError("PCAP file contained zero valid IP or Ethernet packets")

        payload_available = snaplen > 128
        result = {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "status": "valid",
            "packet_count": packet_count,
            "snaplen": snaplen,
            "payload_available": payload_available,
            "link_type": link_type,
            "file_size": file_size,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
        }
        return result

    except Exception as exc:
        logger.warning("PCAP validation failed for run %s: %s", run_id, exc)
        with get_sync_session() as session:
            run = session.execute(
                select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
            ).scalar_one()
            run.status = "failed"
            run.error_step = "validate"
            run.error_message = str(exc)[:1000]
            session.commit()
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Flow Extraction Task
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="workers.pcap_pipeline.pcap_analysis_extract_flows")
def pcap_analysis_extract_flows(
    self,
    prev_result_or_evidence_id: Any,
    run_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Parse packets into bidirectional 5-tuple flows and persist to pcap_flows table."""
    if isinstance(prev_result_or_evidence_id, dict):
        evidence_id = prev_result_or_evidence_id.get("evidence_id")
        run_id = prev_result_or_evidence_id.get("run_id", run_id)
    else:
        evidence_id = int(prev_result_or_evidence_id)

    if not run_id:
        raise ValueError("Missing run_id in pcap_analysis_extract_flows")

    logger.info("Extracting flows for evidence %s (run %s)", evidence_id, run_id)

    with get_sync_session() as session:
        run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one_or_none()
        if run is None:
            raise ValueError(f"Run {run_id} not found in database")
        run.current_step = "extract_flows"
        session.commit()

        evidence = session.execute(
            select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id)
        ).scalar_one_or_none()
        if evidence is None or not evidence.storage_key:
            raise FileNotFoundError("PCAP evidence storage key is unavailable")

        pcap_path = settings.PCAP_STORAGE_DIR / evidence.storage_key

    # Aggregate flows in memory
    flows_map: dict[str, dict[str, Any]] = {}

    try:
        with open_decompressed_pcap(pcap_path) as decompressed_file:
            packet_iterator: Iterator[dict[str, Any]]

            if SCAPY_AVAILABLE:
                try:
                    def _scapy_iter() -> Iterator[dict[str, Any]]:
                        with PcapReader(str(decompressed_file)) as reader:
                            for pkt in reader:
                                ts = datetime.fromtimestamp(float(pkt.time), timezone.utc)
                                length = len(pkt)
                                src_ip = None
                                dst_ip = None
                                proto = None
                                src_port = None
                                dst_port = None
                                dscp = 0
                                fragment_count = 0
                                flags = {}

                                if IP in pkt:
                                    ip_layer = pkt[IP]
                                    src_ip = ip_layer.src
                                    dst_ip = ip_layer.dst
                                    dscp = (ip_layer.tos >> 2) & 0x3F
                                    if ip_layer.frag > 0 or (ip_layer.flags & 1):
                                        fragment_count = 1
                                elif IPv6 in pkt:
                                    ip_layer = pkt[IPv6]
                                    src_ip = ip_layer.src
                                    dst_ip = ip_layer.dst
                                    dscp = (ip_layer.tc >> 2) & 0x3F

                                if not src_ip or not dst_ip:
                                    continue

                                if TCP in pkt:
                                    proto = "tcp"
                                    tcp_layer = pkt[TCP]
                                    src_port = tcp_layer.sport
                                    dst_port = tcp_layer.dport
                                    f_str = str(tcp_layer.flags)
                                    flags = {
                                        "SYN": 1 if "S" in f_str else 0,
                                        "ACK": 1 if "A" in f_str else 0,
                                        "FIN": 1 if "F" in f_str else 0,
                                        "RST": 1 if "R" in f_str else 0,
                                        "PSH": 1 if "P" in f_str else 0,
                                        "URG": 1 if "U" in f_str else 0,
                                    }
                                elif UDP in pkt:
                                    proto = "udp"
                                    udp_layer = pkt[UDP]
                                    src_port = udp_layer.sport
                                    dst_port = udp_layer.dport
                                elif ICMP in pkt:
                                    proto = "icmp"
                                else:
                                    continue

                                yield {
                                    "timestamp": ts,
                                    "length": length,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "protocol": proto,
                                    "dscp": dscp,
                                    "fragment_count": fragment_count,
                                    "flags": flags,
                                }
                    packet_iterator = _scapy_iter()
                except Exception as scapy_err:
                    logger.debug("Scapy stream failed (%s), using pure-python iterator", scapy_err)
                    packet_iterator = _read_pure_python_packets(decompressed_file)
            else:
                packet_iterator = _read_pure_python_packets(decompressed_file)

            for pkt in packet_iterator:
                flow_key, is_forward = normalize_flow_key(
                    pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], pkt["protocol"]
                )
                ts = pkt["timestamp"]
                length = pkt["length"]

                if flow_key not in flows_map:
                    flows_map[flow_key] = {
                        "run_id": run_id,
                        "evidence_id": evidence_id,
                        "src_ip": pkt["src_ip"] if is_forward else pkt["dst_ip"],
                        "dst_ip": pkt["dst_ip"] if is_forward else pkt["src_ip"],
                        "src_port": pkt["src_port"] if is_forward else pkt["dst_port"],
                        "dst_port": pkt["dst_port"] if is_forward else pkt["src_port"],
                        "protocol": pkt["protocol"],
                        "flow_key": flow_key,
                        "packet_count": 0,
                        "byte_count": 0,
                        "reverse_packet_count": 0,
                        "reverse_byte_count": 0,
                        "first_seen": ts,
                        "last_seen": ts,
                        "bidirectional": False,
                        "flags": {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0},
                        "dscp": pkt.get("dscp"),
                        "fragment_count": 0,
                    }

                f_entry = flows_map[flow_key]
                if ts < f_entry["first_seen"]:
                    f_entry["first_seen"] = ts
                if ts > f_entry["last_seen"]:
                    f_entry["last_seen"] = ts

                if is_forward:
                    f_entry["packet_count"] += 1
                    f_entry["byte_count"] += length
                else:
                    f_entry["reverse_packet_count"] += 1
                    f_entry["reverse_byte_count"] += length

                f_entry["bidirectional"] = (f_entry["packet_count"] > 0) and (f_entry["reverse_packet_count"] > 0)
                f_entry["fragment_count"] += pkt.get("fragment_count", 0)

                for flag_k, flag_v in (pkt.get("flags") or {}).items():
                    if flag_v:
                        f_entry["flags"][flag_k] = f_entry["flags"].get(flag_k, 0) + flag_v

        # Persist extracted flows in batches
        db_rows: list[PcapFlows] = []
        for f_data in flows_map.values():
            duration = max(0.0, (f_data["last_seen"] - f_data["first_seen"]).total_seconds())
            flow_row = PcapFlows(
                run_id=f_data["run_id"],
                evidence_id=f_data["evidence_id"],
                src_ip=f_data["src_ip"],
                dst_ip=f_data["dst_ip"],
                src_port=f_data["src_port"],
                dst_port=f_data["dst_port"],
                protocol=f_data["protocol"],
                flow_key=f_data["flow_key"],
                packet_count=f_data["packet_count"],
                byte_count=f_data["byte_count"],
                first_seen=f_data["first_seen"],
                last_seen=f_data["last_seen"],
                duration_seconds=duration,
                bidirectional=f_data["bidirectional"],
                reverse_packet_count=f_data["reverse_packet_count"],
                reverse_byte_count=f_data["reverse_byte_count"],
                flags=f_data["flags"] if f_data["protocol"] == "tcp" else None,
                dscp=f_data["dscp"],
                fragment_count=f_data["fragment_count"],
            )
            db_rows.append(flow_row)

        with get_sync_session() as session:
            # Batch insertion
            batch_size = 500
            for i in range(0, len(db_rows), batch_size):
                session.add_all(db_rows[i:i + batch_size])
                session.flush()

            run = session.execute(
                select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
            ).scalar_one()
            run.current_step = "extract_flows"
            session.commit()

        return {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "flow_count": len(db_rows),
            "status": "flows_extracted",
        }

    except Exception as exc:
        logger.warning("Flow extraction failed for run %s: %s", run_id, exc)
        with get_sync_session() as session:
            run = session.execute(
                select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
            ).scalar_one_or_none()
            if run:
                run.status = "failed"
                run.error_step = "extract_flows"
                run.error_message = str(exc)[:1000]
                session.commit()
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: TCP Session Reconstruction
# ─────────────────────────────────────────────────────────────────────────────

class TCPStreamReassembler:
    """Per-session TCP sequence tracking and bidirectional stream reassembly."""

    def __init__(self, snaplen: int = 65535, max_bytes: int = 10 * 1024 * 1024) -> None:
        self.snaplen = snaplen
        self.max_bytes = max_bytes
        self.state = "open"
        self.syn_seen = False
        self.syn_ack_seen = False
        self.client_isn: int | None = None
        self.server_isn: int | None = None
        self.client_win: int = 0
        self.server_win: int = 0
        self.syn_time: datetime | None = None
        self.established_time: datetime | None = None
        self.close_time: datetime | None = None
        self.last_activity: datetime | None = None

        self.client_expected: int | None = None
        self.server_expected: int | None = None
        self.client_buffer: dict[int, bytes] = {}
        self.server_buffer: dict[int, bytes] = {}
        self.client_stream = bytearray()
        self.server_stream = bytearray()

        self.total_bytes = 0
        self.reassembled_bytes = 0
        self.missing_bytes = 0
        self.retransmit_bytes = 0
        self.ooo_bytes = 0
        self.overlap_bytes = 0

    def add_packet(self, pkt: dict[str, Any], is_client: bool) -> None:
        ts = pkt["timestamp"]
        flags = pkt.get("flags") or {}
        seq = pkt.get("seq", 0)
        win = pkt.get("win", 0)
        payload = pkt.get("payload") or b""
        self.last_activity = ts

        if is_client:
            self.client_win = win
            if flags.get("SYN") and not flags.get("ACK"):
                self.syn_seen = True
                self.syn_time = ts
                self.client_isn = seq
                self.client_expected = (seq + 1) & 0xFFFFFFFF
            elif flags.get("ACK") and self.syn_seen and self.syn_ack_seen and self.state != "established":
                self.state = "established"
                self.established_time = ts
        else:
            self.server_win = win
            if flags.get("SYN") and flags.get("ACK"):
                self.syn_ack_seen = True
                self.server_isn = seq
                self.server_expected = (seq + 1) & 0xFFFFFFFF
                self.state = "half_open"

        if flags.get("RST"):
            self.state = "reset"
            self.close_time = ts
        elif flags.get("FIN"):
            if self.close_time is None:
                self.close_time = ts
            if not self.syn_seen:
                self.state = "closed"

        if payload:
            self._reassemble_direction(payload, seq, is_client)

    def _reassemble_direction(self, payload: bytes, seq: int, is_client: bool) -> None:
        length = len(payload)
        self.total_bytes += length
        expected = self.client_expected if is_client else self.server_expected
        stream = self.client_stream if is_client else self.server_stream
        buf = self.client_buffer if is_client else self.server_buffer

        if expected is None:
            expected = seq
            if is_client:
                self.client_expected = seq
            else:
                self.server_expected = seq

        if seq < expected:
            offset = expected - seq
            if offset >= length:
                self.retransmit_bytes += length
                return
            self.retransmit_bytes += offset
            self.overlap_bytes += offset
            payload = payload[offset:]
            seq = expected

        if seq == expected:
            to_add = min(len(payload), max(0, self.max_bytes - len(stream)))
            if to_add > 0:
                stream.extend(payload[:to_add])
            expected = (expected + length) & 0xFFFFFFFF
            self.reassembled_bytes += length

            while expected in buf:
                next_chunk = buf.pop(expected)
                chunk_len = len(next_chunk)
                to_add = min(chunk_len, max(0, self.max_bytes - len(stream)))
                if to_add > 0:
                    stream.extend(next_chunk[:to_add])
                expected = (expected + chunk_len) & 0xFFFFFFFF
                self.reassembled_bytes += chunk_len
        elif seq > expected:
            self.ooo_bytes += length
            if len(buf) < 1000:
                buf[seq] = payload

        if is_client:
            self.client_expected = expected
        else:
            self.server_expected = expected


@celery_app.task(bind=True, name="workers.pcap_pipeline.pcap_analysis_reconstruct_sessions")
def pcap_analysis_reconstruct_sessions(
    self,
    prev_result_or_evidence_id: Any,
    run_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Reconstruct TCP sequence metrics, OOO/retransmissions, and session state."""
    if isinstance(prev_result_or_evidence_id, dict):
        evidence_id = prev_result_or_evidence_id.get("evidence_id")
        run_id = prev_result_or_evidence_id.get("run_id", run_id)
    else:
        evidence_id = int(prev_result_or_evidence_id)

    if not run_id:
        raise ValueError("Missing run_id in pcap_analysis_reconstruct_sessions")

    logger.info("Reconstructing TCP sessions for evidence %s (run %s)", evidence_id, run_id)

    with get_sync_session() as session:
        run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one_or_none()
        if run is None:
            raise ValueError(f"Run {run_id} not found in database")
        run.current_step = "reconstruct_sessions"
        session.commit()

        evidence = session.execute(
            select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id)
        ).scalar_one_or_none()
        if evidence is None or not evidence.storage_key:
            raise FileNotFoundError("PCAP evidence storage key is unavailable")

        pcap_path = settings.PCAP_STORAGE_DIR / evidence.storage_key

    # Group packets by TCP 4-tuple and reassemble
    sessions_map: dict[str, dict[str, Any]] = {}

    try:
        with open_decompressed_pcap(pcap_path) as decompressed_file:
            packet_iterator: Iterator[dict[str, Any]]

            if SCAPY_AVAILABLE:
                try:
                    def _scapy_iter() -> Iterator[dict[str, Any]]:
                        with PcapReader(str(decompressed_file)) as reader:
                            for pkt in reader:
                                if TCP not in pkt:
                                    continue
                                ts = datetime.fromtimestamp(float(pkt.time), timezone.utc)
                                length = len(pkt)
                                src_ip = None
                                dst_ip = None

                                if IP in pkt:
                                    src_ip = pkt[IP].src
                                    dst_ip = pkt[IP].dst
                                elif IPv6 in pkt:
                                    src_ip = pkt[IPv6].src
                                    dst_ip = pkt[IPv6].dst
                                if not src_ip or not dst_ip:
                                    continue

                                tcp_layer = pkt[TCP]
                                f_str = str(tcp_layer.flags)
                                flags = {
                                    "FIN": 1 if "F" in f_str else 0,
                                    "SYN": 1 if "S" in f_str else 0,
                                    "RST": 1 if "R" in f_str else 0,
                                    "PSH": 1 if "P" in f_str else 0,
                                    "ACK": 1 if "A" in f_str else 0,
                                    "URG": 1 if "U" in f_str else 0,
                                }
                                payload = bytes(tcp_layer.payload) if tcp_layer.payload else b""
                                yield {
                                    "timestamp": ts,
                                    "length": length,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": tcp_layer.sport,
                                    "dst_port": tcp_layer.dport,
                                    "protocol": "tcp",
                                    "flags": flags,
                                    "seq": int(tcp_layer.seq),
                                    "ack": int(tcp_layer.ack),
                                    "win": int(tcp_layer.window),
                                    "payload": payload,
                                }
                    packet_iterator = _scapy_iter()
                except Exception as scapy_err:
                    logger.debug("Scapy session iterator failed (%s), using pure-python parser", scapy_err)
                    packet_iterator = _read_pure_python_packets(decompressed_file)
            else:
                packet_iterator = _read_pure_python_packets(decompressed_file)

            snaplen_observed = 65535
            try:
                with open(decompressed_file, "rb") as f_hdr:
                    gh_bytes = f_hdr.read(24)
                    if len(gh_bytes) >= 20:
                        magic = gh_bytes[:4]
                        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
                        snaplen_observed = struct.unpack(f"{endian}I", gh_bytes[16:20])[0]
            except Exception:
                pass

            for pkt in packet_iterator:
                if pkt.get("protocol") != "tcp":
                    continue

                src_ip = pkt["src_ip"]
                dst_ip = pkt["dst_ip"]
                src_port = pkt["src_port"]
                dst_port = pkt["dst_port"]
                flow_key, _ = normalize_flow_key(src_ip, dst_ip, src_port, dst_port, "tcp")

                flags = pkt.get("flags") or {}
                is_syn = bool(flags.get("SYN") and not flags.get("ACK"))
                is_syn_ack = bool(flags.get("SYN") and flags.get("ACK"))

                if flow_key not in sessions_map:
                    if is_syn_ack:
                        client_ip, client_port = dst_ip, dst_port
                        server_ip, server_port = src_ip, src_port
                    else:
                        client_ip, client_port = src_ip, src_port
                        server_ip, server_port = dst_ip, dst_port

                    sessions_map[flow_key] = {
                        "client_ip": client_ip,
                        "client_port": client_port,
                        "server_ip": server_ip,
                        "server_port": server_port,
                        "first_seen": pkt["timestamp"],
                        "last_seen": pkt["timestamp"],
                        "reassembler": TCPStreamReassembler(snaplen=snaplen_observed),
                    }

                sess_entry = sessions_map[flow_key]
                if is_syn:
                    sess_entry["client_ip"] = src_ip
                    sess_entry["client_port"] = src_port
                    sess_entry["server_ip"] = dst_ip
                    sess_entry["server_port"] = dst_port

                ts = pkt["timestamp"]
                if ts < sess_entry["first_seen"]:
                    sess_entry["first_seen"] = ts
                if ts > sess_entry["last_seen"]:
                    sess_entry["last_seen"] = ts

                is_client = (src_ip == sess_entry["client_ip"] and src_port == sess_entry["client_port"])
                sess_entry["reassembler"].add_packet(pkt, is_client=is_client)

        session_rows: list[TcpSessions] = []
        for flow_k, s_data in sessions_map.items():
            r: TCPStreamReassembler = s_data["reassembler"]
            duration = max(0.0, (s_data["last_seen"] - s_data["first_seen"]).total_seconds())

            if not r.syn_seen and r.state == "open":
                r.state = "incomplete"

            quality = (r.reassembled_bytes / r.total_bytes) if r.total_bytes > 0 else 1.0
            truncated = snaplen_observed <= 128
            if snaplen_observed <= 128:
                confidence = "low"
            elif snaplen_observed < 1500:
                confidence = "medium"
            else:
                confidence = "high"

            row = TcpSessions(
                run_id=run_id,
                evidence_id=evidence_id,
                src_ip=s_data["client_ip"],
                dst_ip=s_data["server_ip"],
                src_port=s_data["client_port"],
                dst_port=s_data["server_port"],
                state=r.state,
                server_isn=r.server_isn,
                client_isn=r.client_isn,
                server_win_size=r.server_win,
                client_win_size=r.client_win,
                total_bytes=r.total_bytes,
                reassembled_bytes=r.reassembled_bytes,
                missing_bytes=r.missing_bytes,
                retransmit_bytes=r.retransmit_bytes,
                ooo_bytes=r.ooo_bytes,
                overlap_bytes=r.overlap_bytes,
                reassembly_quality=round(quality, 4) if quality is not None else None,
                syn_time=r.syn_time,
                established_time=r.established_time,
                close_time=r.close_time,
                last_activity=r.last_activity,
                snaplen=snaplen_observed,
                payload_truncated=truncated,
                confidence=confidence,
                first_seen=s_data["first_seen"],
                last_seen=s_data["last_seen"],
                duration_seconds=duration,
            )
            session_rows.append(row)

        with get_sync_session() as session:
            for i in range(0, len(session_rows), 500):
                session.add_all(session_rows[i:i + 500])
                session.flush()
            session.commit()

        return {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "session_count": len(session_rows),
            "status": "sessions_reconstructed",
        }

    except Exception as exc:
        logger.warning("Session reconstruction failed for run %s: %s", run_id, exc)
        with get_sync_session() as session:
            run = session.execute(
                select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
            ).scalar_one_or_none()
            if run:
                run.status = "failed"
                run.error_step = "reconstruct_sessions"
                run.error_message = str(exc)[:1000]
                session.commit()
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Forensic Artifact Extraction (HTTP / DNS / TLS)
# ─────────────────────────────────────────────────────────────────────────────

def parse_http_messages(stream: bytes) -> list[dict[str, Any]]:
    """Parse HTTP request and response structures from reassembled stream bytes."""
    results: list[dict[str, Any]] = []
    if not stream:
        return results

    import re
    # Match HTTP request
    req_match = re.search(rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s\r\n]+)\s+HTTP/(\d\.\d)\r\n", stream)
    if req_match:
        hdr_start = req_match.start()
        hdr_end = stream.find(b"\r\n\r\n", hdr_start)
        if hdr_end != -1:
            header_text = stream[hdr_start:hdr_end].decode("latin-1", errors="replace")
            lines = header_text.split("\r\n")
            first_line = lines[0].split(None, 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            body_start = hdr_end + 4
            content_len_hdr = headers.get("content-length")
            try:
                content_len = int(content_len_hdr) if content_len_hdr else len(stream) - body_start
            except ValueError:
                content_len = len(stream) - body_start

            body = stream[body_start:body_start + max(0, min(content_len, 10 * 1024 * 1024))]
            results.append({
                "type": "http_request",
                "method": first_line[0],
                "uri": first_line[1] if len(first_line) > 1 else "/",
                "headers": headers,
                "content_type": headers.get("content-type", "application/octet-stream"),
                "content_length": len(body),
                "body": body,
            })

    # Match HTTP response
    resp_match = re.search(rb"HTTP/(\d\.\d)\s+(\d{3})\s*([^\r\n]*)\r\n", stream)
    if resp_match:
        hdr_start = resp_match.start()
        hdr_end = stream.find(b"\r\n\r\n", hdr_start)
        if hdr_end != -1:
            header_text = stream[hdr_start:hdr_end].decode("latin-1", errors="replace")
            lines = header_text.split("\r\n")
            status_parts = lines[0].split(None, 2)
            status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 200
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            body_start = hdr_end + 4
            content_len_hdr = headers.get("content-length")
            try:
                content_len = int(content_len_hdr) if content_len_hdr else len(stream) - body_start
            except ValueError:
                content_len = len(stream) - body_start

            body = stream[body_start:body_start + max(0, min(content_len, 10 * 1024 * 1024))]
            results.append({
                "type": "http_response",
                "status_code": status_code,
                "headers": headers,
                "content_type": headers.get("content-type", "text/html"),
                "content_length": len(body),
                "body": body,
            })

    return results


def parse_dns_packet(payload: bytes) -> dict[str, Any] | None:
    """Parse standard DNS queries and responses from packet payload bytes."""
    if len(payload) < 12:
        return None
    tid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", payload[:12])
    is_response = bool(flags & 0x8000)
    offset = 12

    # Parse query name
    labels = []
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            offset += 2
            break
        offset += 1
        if offset + length > len(payload):
            break
        labels.append(payload[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length

    qname = ".".join(labels)
    if offset + 4 <= len(payload):
        qtype, _qclass = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
    else:
        qtype = 1

    answers = []
    for _ in range(ancount):
        if offset >= len(payload):
            break
        if (payload[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while offset < len(payload) and payload[offset] != 0:
                offset += 1 + payload[offset]
            offset += 1
        if offset + 10 <= len(payload):
            atype, _aclass, ttl, rdlen = struct.unpack("!HHIH", payload[offset:offset + 10])
            offset += 10
            rdata_bytes = payload[offset:offset + rdlen]
            offset += rdlen
            if atype == 1 and rdlen == 4:
                import socket
                rdata = socket.inet_ntoa(rdata_bytes)
            else:
                rdata = rdata_bytes.hex()
            answers.append({"type": atype, "ttl": ttl, "rdata": rdata})

    return {
        "transaction_id": tid,
        "is_response": is_response,
        "query_name": qname,
        "query_type": qtype,
        "answers": answers,
    }


def parse_tls_client_hello(payload: bytes) -> dict[str, Any] | None:
    """Extract SNI hostname, supported groups, and compute JA3 hash from ClientHello."""
    import hashlib
    if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return None

    ver = (payload[9] << 8) | payload[10]
    sess_id_len = payload[43]
    offset = 44 + sess_id_len
    if len(payload) < offset + 2:
        return None

    ciphers_len = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2
    ciphers = []
    for i in range(0, ciphers_len, 2):
        if offset + i + 2 > len(payload):
            break
        c = struct.unpack("!H", payload[offset + i:offset + i + 2])[0]
        if (c & 0x0F0F) != 0x0A0A:  # Filter GREASE ciphers
            ciphers.append(c)
    offset += ciphers_len

    if len(payload) < offset + 1:
        return None
    comp_len = payload[offset]
    offset += 1 + comp_len

    if len(payload) < offset + 2:
        return None
    exts_len = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2

    extensions = []
    curves = []
    points = []
    sni = None
    ext_end = min(len(payload), offset + exts_len)

    while offset + 4 <= ext_end:
        etype, elen = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
        edata = payload[offset:offset + elen]
        offset += elen

        if (etype & 0x0F0F) != 0x0A0A:
            extensions.append(etype)
        if etype == 0:  # Server Name Indication (SNI)
            if len(edata) >= 5:
                name_len = struct.unpack("!H", edata[3:5])[0]
                sni = edata[5:5 + name_len].decode("utf-8", errors="replace")
        elif etype == 10:  # Supported groups / Elliptic Curves
            if len(edata) >= 2:
                g_len = struct.unpack("!H", edata[:2])[0]
                for j in range(2, min(len(edata), 2 + g_len), 2):
                    g = struct.unpack("!H", edata[j:j + 2])[0]
                    if (g & 0x0F0F) != 0x0A0A:
                        curves.append(g)
        elif etype == 11:  # EC Point Formats
            if len(edata) >= 1:
                p_len = edata[0]
                points = list(edata[1:1 + p_len])

    ja3_str = f"{ver},{'-'.join(map(str, ciphers))},{'-'.join(map(str, extensions))},{'-'.join(map(str, curves))},{'-'.join(map(str, points))}"
    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
    return {"sni": sni, "ja3_hash": ja3_hash, "ja3_string": ja3_str, "version": hex(ver)}


@celery_app.task(bind=True, name="workers.pcap_pipeline.pcap_analysis_extract_artifacts")
def pcap_analysis_extract_artifacts(
    self,
    prev_result_or_evidence_id: Any,
    run_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Extract HTTP bodies, DNS metadata, and TLS ClientHello/JA3 records to storage."""
    if isinstance(prev_result_or_evidence_id, dict):
        evidence_id = prev_result_or_evidence_id.get("evidence_id")
        run_id = prev_result_or_evidence_id.get("run_id", run_id)
    else:
        evidence_id = int(prev_result_or_evidence_id)

    if not run_id:
        raise ValueError("Missing run_id in pcap_analysis_extract_artifacts")

    logger.info("Extracting artifacts for evidence %s (run %s)", evidence_id, run_id)
    storage = get_storage_backend()
    staging_prefix = f"analysis-{run_id}"

    with get_sync_session() as session:
        run = session.execute(
            select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
        ).scalar_one_or_none()
        if run is None:
            raise ValueError(f"Run {run_id} not found in database")
        run.current_step = "extract_artifacts"
        session.commit()

        evidence = session.execute(
            select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id)
        ).scalar_one_or_none()
        if evidence is None or not evidence.storage_key:
            raise FileNotFoundError("PCAP evidence storage key is unavailable")

        pcap_path = settings.PCAP_STORAGE_DIR / evidence.storage_key

    artifacts_to_insert: list[PcapArtifacts] = []

    try:
        with open_decompressed_pcap(pcap_path) as decompressed_file:
            packet_iterator: Iterator[dict[str, Any]]
            if SCAPY_AVAILABLE:
                try:
                    def _scapy_iter() -> Iterator[dict[str, Any]]:
                        with PcapReader(str(decompressed_file)) as reader:
                            for pkt in reader:
                                ts = datetime.fromtimestamp(float(pkt.time), timezone.utc)
                                proto = None
                                src_port = None
                                dst_port = None
                                payload = b""

                                if TCP in pkt:
                                    proto = "tcp"
                                    src_port = pkt[TCP].sport
                                    dst_port = pkt[TCP].dport
                                    payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                                elif UDP in pkt:
                                    proto = "udp"
                                    src_port = pkt[UDP].sport
                                    dst_port = pkt[UDP].dport
                                    payload = bytes(pkt[UDP].payload) if pkt[UDP].payload else b""
                                else:
                                    continue

                                yield {
                                    "timestamp": ts,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "protocol": proto,
                                    "payload": payload,
                                }
                    packet_iterator = _scapy_iter()
                except Exception as scapy_err:
                    logger.debug("Scapy stream failed (%s), using pure-python iterator", scapy_err)
                    packet_iterator = _read_pure_python_packets(decompressed_file)
            else:
                packet_iterator = _read_pure_python_packets(decompressed_file)

            for pkt in packet_iterator:
                payload = pkt.get("payload") or b""
                if not payload:
                    continue

                proto = pkt.get("protocol")
                src_port = pkt.get("src_port")
                dst_port = pkt.get("dst_port")

                # 1. DNS extraction (Port 53)
                if src_port == 53 or dst_port == 53:
                    dns_info = parse_dns_packet(payload)
                    if dns_info and dns_info.get("query_name"):
                        art_type = "dns_response" if dns_info["is_response"] else "dns_query"
                        artifacts_to_insert.append(
                            PcapArtifacts(
                                run_id=run_id,
                                evidence_id=evidence_id,
                                artifact_type=art_type,
                                storage_prefix=staging_prefix,
                                metadata_json=dns_info,
                                size_bytes=len(payload),
                            )
                        )

                # 2. TLS ClientHello extraction (Port 443, 8443 or TLS record)
                if proto == "tcp" and (dst_port in (443, 8443) or payload.startswith(b"\x16\x03")):
                    tls_info = parse_tls_client_hello(payload)
                    if tls_info:
                        artifacts_to_insert.append(
                            PcapArtifacts(
                                run_id=run_id,
                                evidence_id=evidence_id,
                                artifact_type="tls_client_hello",
                                storage_prefix=staging_prefix,
                                metadata_json=tls_info,
                                size_bytes=len(payload),
                            )
                        )
                        # Standalone JA3 artifact
                        if tls_info.get("ja3_hash"):
                            artifacts_to_insert.append(
                                PcapArtifacts(
                                    run_id=run_id,
                                    evidence_id=evidence_id,
                                    artifact_type="tls_ja3",
                                    storage_prefix=staging_prefix,
                                    metadata_json={"ja3_hash": tls_info["ja3_hash"], "ja3_string": tls_info["ja3_string"]},
                                    size_bytes=len(tls_info["ja3_hash"]),
                                )
                            )

                # 3. HTTP extraction
                if proto == "tcp" and (
                    src_port in (80, 8080, 8000) or dst_port in (80, 8080, 8000)
                    or payload.startswith(b"GET ") or payload.startswith(b"POST ")
                    or payload.startswith(b"HTTP/")
                ):
                    http_msgs = parse_http_messages(payload)
                    for msg in http_msgs:
                        body_bytes = msg.pop("body", b"")
                        storage_key = None
                        sha256_hash = None
                        if body_bytes:
                            # Save body payload to storage backend
                            content_ext = "html" if "html" in msg.get("content_type", "") else "bin"
                            storage_key, sha256_hash = storage.save_artifact(
                                prefix=staging_prefix, content=body_bytes, extension=content_ext
                            )

                        artifacts_to_insert.append(
                            PcapArtifacts(
                                run_id=run_id,
                                evidence_id=evidence_id,
                                artifact_type=msg["type"],
                                content_type=msg.get("content_type"),
                                content_length=msg.get("content_length"),
                                sha256=sha256_hash,
                                storage_key=storage_key,
                                storage_prefix=staging_prefix,
                                metadata_json=msg,
                                size_bytes=len(body_bytes),
                            )
                        )

        # Persist artifacts and complete analysis run
        with get_sync_session() as session:
            for i in range(0, len(artifacts_to_insert), 500):
                session.add_all(artifacts_to_insert[i:i + 500])
                session.flush()

            run = session.execute(
                select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
            ).scalar_one()
            run.status = "complete"
            run.completed_at = datetime.now(timezone.utc)
            session.commit()

        return {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "artifact_count": len(artifacts_to_insert),
            "status": "complete",
        }

    except Exception as exc:
        logger.warning("Artifact extraction failed for run %s: %s", run_id, exc)
        with get_sync_session() as session:
            run = session.execute(
                select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)
            ).scalar_one_or_none()
            if run:
                run.status = "failed"
                run.error_step = "extract_artifacts"
                run.error_message = str(exc)[:1000]
                session.commit()
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher: Entry point for analysis chain
# ─────────────────────────────────────────────────────────────────────────────

def start_pcap_analysis(evidence_id: int, run_id: str | None = None) -> str:
    """Initialize analysis run and launch the Celery task chain through all phases."""
    run_id = run_id or uuid4().hex

    with get_sync_session() as session:
        evidence = session.execute(
            select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id)
        ).scalar_one_or_none()
        if evidence is None:
            raise ValueError(f"Evidence {evidence_id} not found")

        # Create tracking record
        analysis_run = PcapAnalysisRuns(
            run_id=run_id,
            evidence_id=evidence_id,
            investigation_id=evidence.investigation_id,
            node_id=evidence.node_id,
            status="pending",
            current_step="validate",
            started_at=datetime.now(timezone.utc),
        )
        session.add(analysis_run)
        session.commit()

    pipeline_chain = chain(
        pcap_analysis_validate.s(evidence_id, run_id),
        pcap_analysis_extract_flows.s(run_id=run_id),
        pcap_analysis_reconstruct_sessions.s(run_id=run_id),
        pcap_analysis_extract_artifacts.s(run_id=run_id),
    )
    pipeline_chain.apply_async()
    logger.info("Enqueued PCAP analysis pipeline for evidence %s with run_id %s", evidence_id, run_id)
    return run_id
