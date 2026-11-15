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
from models.investigation_evidence import InvestigationEvidence
from models.pcap_analysis import PcapAnalysisRuns, PcapFlows
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# Scapy import with fallback
try:
    from scapy.all import (
        Dot1Q,
        Ether,
        ICMP,
        IP,
        IPv6,
        PcapReader,
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
        if len(data) >= l4_offset + 14:
            src_port, dst_port, _seq, _ack, data_offset_flags = struct.unpack("!HHIIH", data[l4_offset:l4_offset + 14])
            tcp_flags = data_offset_flags & 0x01FF
            flags = {
                "FIN": 1 if tcp_flags & 0x01 else 0,
                "SYN": 1 if tcp_flags & 0x02 else 0,
                "RST": 1 if tcp_flags & 0x04 else 0,
                "PSH": 1 if tcp_flags & 0x08 else 0,
                "ACK": 1 if tcp_flags & 0x10 else 0,
                "URG": 1 if tcp_flags & 0x20 else 0,
            }
    elif proto_num == 17:  # UDP
        proto = "udp"
        if len(data) >= l4_offset + 4:
            src_port, dst_port = struct.unpack("!HH", data[l4_offset:l4_offset + 4])
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
            run.status = "complete"
            run.completed_at = datetime.now(timezone.utc)
            session.commit()

        return {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "flow_count": len(db_rows),
            "status": "complete",
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
# Dispatcher: Entry point for analysis chain
# ─────────────────────────────────────────────────────────────────────────────

def start_pcap_analysis(evidence_id: int, run_id: str | None = None) -> str:
    """Initialize analysis run and launch the Celery task chain."""
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
    )
    pipeline_chain.apply_async()
    logger.info("Enqueued PCAP analysis pipeline for evidence %s with run_id %s", evidence_id, run_id)
    return run_id
