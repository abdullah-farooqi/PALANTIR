"""Bounded tcpdump capture manager used by the host collector."""

from __future__ import annotations

import gzip
import hashlib
import json
import mmap
import os
import queue
import re
import shutil
import signal
import struct
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


_FILE_ID = re.compile(r"^capture_\d{8}T\d{6}Z_[0-9a-f]{12}\.pcap\d*$")
_COMPRESSION_ALIASES = {"none": "none", "gz": "gzip", "gzip": "gzip", "zst": "zstd", "zstd": "zstd"}


class PCapError(RuntimeError):
    """A capture operation failed or is unavailable."""


class PCapFileNotReady(PCapError):
    """A capture exists but has not finished compression yet."""


def normalize_compression(value: str | None) -> str:
    """Map collector suffix/config aliases to the contract vocabulary."""
    if not value:
        return "none"
    try:
        return _COMPRESSION_ALIASES[value]
    except KeyError as exc:
        raise ValueError(f"unsupported PCAP compression: {value}") from exc


def build_bpf_filter(exclude_expression: str) -> str:
    """Wrap a BPF expression as an exclusion without invoking a shell."""
    expression = exclude_expression.strip()
    return f"not ({expression})" if expression else ""


def _pcap_packet_info(path: Path) -> tuple[tuple[datetime, datetime] | None, int | None]:
    """Read packet bounds and count from a classic pcap without loading payloads."""
    try:
        with path.open("rb") as stream:
            if path.stat().st_size < 24:
                return None, None
            with mmap.mmap(stream.fileno(), length=0, access=mmap.ACCESS_READ) as data:
                formats = {
                    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
                    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
                    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
                    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
                }
                encoding = formats.get(data[:4])
                if encoding is None:
                    return None, None
                endian, fraction_scale = encoding
                packet_header = struct.Struct(f"{endian}IIII")
                file_size = len(data)
                offset = 24
                first_timestamp = last_timestamp = None
                packet_count = 0
                while offset + packet_header.size <= file_size:
                    seconds, fraction, captured_length, _original_length = packet_header.unpack_from(data, offset)
                    packet_offset = offset + packet_header.size
                    if captured_length > 262144 or packet_offset + captured_length > file_size:
                        return None, None
                    timestamp = seconds + fraction / fraction_scale
                    if first_timestamp is None:
                        first_timestamp = timestamp
                    last_timestamp = timestamp
                    packet_count += 1
                    offset = packet_offset + captured_length
                if first_timestamp is None or last_timestamp is None:
                    return None, packet_count
                bounds = (
                    datetime.fromtimestamp(first_timestamp, timezone.utc),
                    datetime.fromtimestamp(last_timestamp, timezone.utc),
                )
                return bounds, packet_count
    except (OSError, OverflowError, ValueError, struct.error):
        return None, None


def _pcap_packet_bounds(path: Path) -> tuple[datetime, datetime] | None:
    return _pcap_packet_info(path)[0]


class PCapManager:
    """Own a tcpdump process, rotate bounded files, and compress closed captures.

    The collector rotates the tcpdump process on a time interval. tcpdump's ``-C``
    option splits high-volume intervals into bounded files. The manager retains at
    most ``max_files`` unpinned files; a busy host can therefore have less than the
    configured time window available. A snapshot closes the active file, pins the
    retained files, and resumes capture before returning its manifest.
    """

    def __init__(
        self,
        *,
        enabled: bool,
        interface: str,
        snaplen: int,
        rotation_seconds: int,
        max_files: int,
        max_size_mb: int,
        filter_exclude: str,
        storage_dir: Path,
        compression: str,
        snapshot_ttl_seconds: int = 1800,
        max_active_snapshots: int = 3,
        alert_snaplen: int | None = None,
        alert_window_seconds: int = 10,
        max_total_bytes: int | None = None,
    ) -> None:
        if not interface or len(interface) > 64:
            raise ValueError("PCAP_INTERFACE must be a non-empty interface name")
        if not 64 <= snaplen <= 262144:
            raise ValueError("PCAP_SNAPLEN must be between 64 and 262144")
        if not 30 <= rotation_seconds <= 86400:
            raise ValueError("PCAP_ROTATION_SECONDS must be between 30 and 86400")
        if not 1 <= max_files <= 100:
            raise ValueError("PCAP_MAX_FILES must be between 1 and 100")
        if not 1 <= max_size_mb <= 4096:
            raise ValueError("PCAP_MAX_SIZE_MB must be between 1 and 4096")
        if compression not in {"zstd", "gzip", "none"}:
            raise ValueError("PCAP_COMPRESSION must be zstd, gzip, or none")
        if not 1 <= max_active_snapshots <= 100:
            raise ValueError("PCAP_MAX_ACTIVE_SNAPSHOTS must be between 1 and 100")
        alert_snaplen = alert_snaplen if alert_snaplen is not None else snaplen
        if not snaplen <= alert_snaplen <= 262144:
            raise ValueError("PCAP_ALERT_SNAPLEN must be between PCAP_SNAPLEN and 262144")
        if not 1 <= alert_window_seconds <= 30:
            raise ValueError("PCAP_ALERT_WINDOW_SECONDS must be between 1 and 30")

        self.enabled = enabled
        self.interface = interface
        self.snaplen = snaplen
        self.rotation_seconds = rotation_seconds
        self.max_files = max_files
        self.max_size_mb = max_size_mb
        self.filter_exclude = filter_exclude
        self.storage_dir = storage_dir
        self.compression = compression
        self.snapshot_ttl_seconds = max(60, snapshot_ttl_seconds)
        self.max_active_snapshots = max_active_snapshots
        self.default_snaplen = snaplen
        self.alert_snaplen = alert_snaplen
        self.alert_window_seconds = alert_window_seconds
        self.max_total_bytes = max_total_bytes if max_total_bytes is not None else max_size_mb * max_files * 1024 * 1024
        if self.max_total_bytes < max_size_mb * 1024 * 1024:
            raise ValueError("PCAP_MAX_TOTAL_SIZE_MB must be at least PCAP_MAX_SIZE_MB")

        self._lock = threading.RLock()
        self._snapshot_call_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._snapshot_requested = threading.Event()
        self._snapshot_completed = threading.Event()
        self._alert_requested = threading.Event()
        self._alert_started = threading.Event()
        self._alert_until: float | None = None
        self._compression_queue: queue.Queue[Path | None] = queue.Queue(maxsize=max(8, max_files * 4))
        self._hash_queue: queue.Queue[tuple[Path, str] | None] = queue.Queue(maxsize=max(8, max_files * 4))
        self._compressing: set[str] = set()
        self._pins: dict[str, dict[str, Any]] = {}
        self._thread: threading.Thread | None = None
        self._compression_thread: threading.Thread | None = None
        self._hash_thread: threading.Thread | None = None
        self._process: subprocess.Popen | None = None
        self._current_prefix: Path | None = None
        self._current_started_at: datetime | None = None
        self._snapshot_result: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._dropped_files = 0
        self._last_started_at: str | None = None
        self._runtime_enabled = enabled

        self._pins_dir = self.storage_dir / ".snapshots"
        self._load_pins()

    def start(self) -> bool:
        """Start capture if the process is not already running."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                if self._stop_event.is_set():
                    self._last_error = "Packet capture is still stopping; retry shortly"
                    return False
                self._runtime_enabled = True
                return True
            if shutil.which("tcpdump") is None:
                self._last_error = "tcpdump is not installed in the collector image"
                return False
            try:
                self.storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                self._pins_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            except OSError as exc:
                self._last_error = f"PCAP storage is not writable: {exc}"
                return False
            self._runtime_enabled = True
            self.snaplen = self.default_snaplen
            self._alert_until = None
            self._alert_requested.clear()
            self._alert_started.clear()
            self._stop_event.clear()
            self._snapshot_requested.clear()
            self._snapshot_completed.clear()
            self._snapshot_result = None
            self._ensure_compressor()
            self._ensure_hash_worker()
            self._recover_closed_files()
            self._thread = threading.Thread(target=self._run, name="palantir-pcap", daemon=True)
            self._thread.start()
            return True

    def stop(self, timeout: float = 10.0) -> None:
        """Stop tcpdump gracefully and close the active capture file."""
        with self._lock:
            thread = self._thread
            self._runtime_enabled = False
            self._stop_event.set()
            self._snapshot_requested.set()
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.1, timeout))
        with self._lock:
            if thread and thread.is_alive():
                self._last_error = "Timed out while stopping tcpdump; capture may still be shutting down"
                return
            self._thread = None
            self._process = None
            self._current_prefix = None
            self._current_started_at = None
        self._prune()

    def snapshot(self, timeout: float = 25.0, trigger_type: str = "manual") -> dict[str, Any]:
        """Close the active segment and return a pinned manifest of retained files."""
        if trigger_type not in {"manual", "alert", "anomaly"}:
            raise PCapError("Unknown PCAP snapshot trigger type")
        if not self.status()["running"]:
            raise PCapError("Packet capture is not running")
        with self._snapshot_call_lock:
            if trigger_type == "alert" and self.alert_snaplen > self.default_snaplen:
                self._alert_started.clear()
                self._alert_requested.set()
                if not self._alert_started.wait(timeout=8.0):
                    raise PCapError("Timed out while starting the alert capture window")
                with self._lock:
                    alert_until = self._alert_until
                if alert_until is not None:
                    time.sleep(max(0.0, alert_until - time.monotonic()))
                timeout = max(timeout, self.alert_window_seconds + 20.0)
            # Allow time to rotate, compress, and finish SHA-256 before handoff.
            timeout = max(timeout, 25.0)
            self._snapshot_completed.clear()
            self._snapshot_result = None
            self._snapshot_requested.set()
            if not self._snapshot_completed.wait(timeout=max(0.1, timeout)):
                raise PCapError("Timed out while finalizing the active PCAP segment")
            if self._snapshot_result is None:
                raise PCapError("The collector could not create a PCAP snapshot")
            return {**self._snapshot_result, "trigger_type": trigger_type}

    def release_snapshot(self, snapshot_id: str) -> bool:
        """Release files pinned for a completed or expired evidence transfer."""
        if not re.fullmatch(r"[0-9a-f]{32}", snapshot_id):
            return False
        with self._lock:
            existed = self._pins.pop(snapshot_id, None) is not None
        try:
            (self._pins_dir / f"{snapshot_id}.json").unlink(missing_ok=True)
        except OSError:
            pass
        self._prune()
        return existed

    def files(self, snapshot_id: str | None = None) -> list[dict[str, Any]]:
        """List finalized PCAP artifacts, optionally limited to a pinned snapshot."""
        self._expire_pins()
        with self._lock:
            if snapshot_id and snapshot_id not in self._pins:
                return []
            pinned = self._pins.get(snapshot_id, {}).get("file_ids") if snapshot_id else None
        wanted = set(pinned) if pinned is not None else None
        results: list[dict[str, Any]] = []
        for metadata_path in sorted(self.storage_dir.glob("capture_*.pcap*.json")):
            try:
                metadata = json.loads(metadata_path.read_text())
                file_id = metadata.get("file_id")
                if not isinstance(file_id, str) or not _FILE_ID.fullmatch(file_id):
                    continue
                if wanted is not None and file_id not in wanted:
                    continue
                raw_path, final_path = self._artifact_paths(file_id)
                if not raw_path.exists() and not final_path.exists():
                    continue
                with self._lock:
                    is_compressing = file_id in self._compressing
                selected_path = final_path if final_path.exists() else raw_path
                if is_compressing:
                    expected_compression = self._normalize_compression_label(self.compression)
                    expected_name = final_path.name
                elif selected_path != raw_path:
                    expected_compression = self._normalize_compression_label(
                        selected_path.suffix.removeprefix(".")
                    )
                    expected_name = selected_path.name
                else:
                    expected_compression = "none"
                    expected_name = selected_path.name
                original_size = metadata.get("original_size_bytes")
                if isinstance(original_size, bool) or not isinstance(original_size, int) or original_size < 0:
                    original_size = None
                snaplen = metadata.get("snaplen")
                if isinstance(snaplen, bool) or not isinstance(snaplen, int) or snaplen < 1:
                    snaplen = None
                packet_count = metadata.get("packet_count")
                if isinstance(packet_count, bool) or not isinstance(packet_count, int) or packet_count < 0:
                    packet_count = None
                sha256 = metadata.get("sha256")
                if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
                    sha256 = None
                hash_status = metadata.get("hash_status", "pending")
                if hash_status not in {"pending", "complete", "unavailable", "queue_full"}:
                    hash_status = "pending"
                if hash_status == "complete" and sha256 is None:
                    hash_status = "pending"
                results.append({
                    "file_id": file_id,
                    "filename": expected_name,
                    "size_bytes": selected_path.stat().st_size,
                    "original_size_bytes": original_size,
                    "capture_started_at": metadata.get("capture_started_at"),
                    "capture_finished_at": metadata.get("capture_finished_at"),
                    "duration_seconds": metadata.get("duration_seconds"),
                    "compression": expected_compression,
                    "status": "compressing" if is_compressing else "ready",
                    "interface": metadata.get("interface") if isinstance(metadata.get("interface"), str) else None,
                    "snaplen": snaplen,
                    "packet_count": packet_count,
                    "sha256": sha256,
                    "hash_status": hash_status,
                })
            except (OSError, ValueError, TypeError):
                continue
        return results

    def file_path(self, file_id: str) -> tuple[Path, str]:
        """Resolve an opaque capture ID to an immutable, finalized artifact path."""
        if not _FILE_ID.fullmatch(file_id):
            raise FileNotFoundError("Invalid PCAP file ID")
        with self._lock:
            if file_id in self._compressing:
                raise PCapFileNotReady("PCAP file compression is still in progress")
        if not self._metadata_path(file_id).is_file():
            raise FileNotFoundError("PCAP file is not finalized")
        raw_path, final_path = self._artifact_paths(file_id)
        path = final_path if final_path.is_file() else raw_path
        try:
            path.resolve(strict=True).relative_to(self.storage_dir.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise FileNotFoundError("PCAP file not found") from exc
        if not path.is_file():
            raise FileNotFoundError("PCAP file not found")
        media_type = "application/zstd" if path.suffix == ".zst" else (
            "application/gzip" if path.suffix == ".gz" else "application/vnd.tcpdump.pcap"
        )
        return path, media_type

    def status(self) -> dict[str, Any]:
        files = self.files()
        try:
            usage = shutil.disk_usage(self.storage_dir)
            disk = {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}
        except OSError:
            disk = None
        with self._lock:
            process = self._process
            running = bool(process and process.poll() is None)
            error = self._last_error
            started = self._last_started_at
            enabled = self._runtime_enabled
            active_snapshots = len(self._pins)
            dropped_files = self._dropped_files
        retained_bytes = sum(int(item.get("size_bytes") or 0) for item in files)
        return {
            "enabled": enabled,
            "configured_enabled": self.enabled,
            "running": running,
            "pid": process.pid if running and process else None,
            "interface": self.interface,
            "snaplen": self.snaplen,
            "alert_snaplen": self.alert_snaplen,
            "alert_window_seconds": self.alert_window_seconds,
            "rotation_seconds": self.rotation_seconds,
            "max_files": self.max_files,
            "max_size_mb": self.max_size_mb,
            "max_total_bytes": self.max_total_bytes,
            "dropped_files": dropped_files,
            "active_snapshots": active_snapshots,
            "max_active_snapshots": self.max_active_snapshots,
            "filter": build_bpf_filter(self.filter_exclude),
            "compression": self.compression,
            "file_count": len(files),
            "retained_bytes": retained_bytes,
            "disk": disk,
            "last_started_at": started,
            "last_error": error,
            "coverage_seconds": self._coverage_seconds(files),
        }

    def _build_tcpdump_command(self, prefix: Path) -> list[str]:
        command = [
            "tcpdump", "-n", "-U", "-i", self.interface,
            "-s", str(self.snaplen), "-B", "4096",
            "-C", str(self.max_size_mb), "-W", str(self.max_files),
            "-w", str(prefix),
        ]
        filter_expression = build_bpf_filter(self.filter_exclude)
        if filter_expression:
            command.append(filter_expression)
        return command

    def _run(self) -> None:
        backoff = 1.0
        while not self._stop_event.is_set():
            started_at = datetime.now(timezone.utc)
            prefix = self.storage_dir / (
                f"capture_{started_at.strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:12]}.pcap"
            )
            command = self._build_tcpdump_command(prefix)
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
            except (OSError, ValueError) as exc:
                with self._lock:
                    self._last_error = f"Could not start tcpdump: {exc}"
                self._stop_event.wait(backoff)
                backoff = min(30.0, backoff * 2)
                continue

            with self._lock:
                self._process = process
                self._current_prefix = prefix
                self._current_started_at = started_at
                self._last_started_at = started_at.isoformat()
                self._last_error = None
                if self.snaplen == self.alert_snaplen and self.alert_snaplen > self.default_snaplen and self._alert_until is None:
                    self._alert_until = time.monotonic() + self.alert_window_seconds
                    self._alert_started.set()
            backoff = 1.0
            deadline = time.monotonic() + self.rotation_seconds
            reason = "time"
            while not self._stop_event.is_set():
                wait_seconds = min(1.0, max(0.05, deadline - time.monotonic()))
                if self._alert_requested.wait(timeout=wait_seconds):
                    self._alert_requested.clear()
                    reason = "alert_start"
                    break
                if self._snapshot_requested.is_set():
                    reason = "snapshot"
                    break
                if process.poll() is not None:
                    reason = "process_exit"
                    break
                with self._lock:
                    alert_until = self._alert_until
                if alert_until is not None and time.monotonic() >= alert_until:
                    reason = "alert_end"
                    break
                if time.monotonic() >= deadline:
                    reason = "time"
                    break
            if self._stop_event.is_set():
                reason = "stop"

            self._stop_process(process)
            self._register_closed_files(prefix, started_at)
            self._prune()
            with self._lock:
                self._process = None
                self._current_prefix = None
                self._current_started_at = None

            if reason == "alert_start":
                with self._lock:
                    self.snaplen = self.alert_snaplen
                    self._alert_until = None
                continue
            if reason == "alert_end":
                with self._lock:
                    self.snaplen = self.default_snaplen
                    self._alert_until = None
                continue

            if reason == "snapshot":
                snapshot_id = uuid4().hex
                available = self.files()
                recent = sorted(available, key=self._file_recency, reverse=True)[:self.max_files]
                file_ids = [item["file_id"] for item in recent]
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.snapshot_ttl_seconds)
                if self._pin(snapshot_id, file_ids, expires_at):
                    # Backend transfer requires ready + complete SHA-256; wait before handoff.
                    ready_files = self._await_files_transfer_ready(
                        file_ids,
                        timeout=min(15.0, max(5.0, float(self.rotation_seconds))),
                    )
                    self._snapshot_result = {
                        "snapshot_id": snapshot_id,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "expires_at": expires_at.isoformat(),
                        "coverage_seconds": self._coverage_seconds(ready_files),
                        "files": ready_files,
                    }
                else:
                    self._snapshot_result = None
                self._snapshot_requested.clear()
                self._snapshot_completed.set()
            elif reason == "process_exit" and not self._stop_event.is_set():
                with self._lock:
                    self._last_error = f"tcpdump exited unexpectedly with status {process.returncode}"
                self._stop_event.wait(backoff)
                backoff = min(30.0, backoff * 2)
            else:
                with self._lock:
                    self._last_error = None
            self._prune()

        # A shutdown closes the active file and makes it available after restart.
        with self._lock:
            process = self._process
            prefix = self._current_prefix
            started_at = self._current_started_at
        if process:
            self._stop_process(process)
        if prefix and started_at:
            self._register_closed_files(prefix, started_at)
        with self._lock:
            self._process = None
            self._current_prefix = None
            self._current_started_at = None
            if self._snapshot_requested.is_set():
                self._snapshot_result = None
                self._snapshot_requested.clear()
                self._snapshot_completed.set()

    @staticmethod
    def _stop_process(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        except OSError:
            pass

    def _register_closed_files(self, prefix: Path, started_at: datetime) -> None:
        finished_at = datetime.now(timezone.utc)
        candidates = [
            path for path in self.storage_dir.glob(f"{prefix.name}*")
            if path.is_file() and _FILE_ID.fullmatch(path.name)
        ]
        for path in candidates:
            metadata_path = self._metadata_path(path.name)
            try:
                size_bytes = path.stat().st_size
            except OSError:
                continue
            if size_bytes <= 24:
                self._delete_artifact(path.name)
                continue
            exact_process_file = path.name == prefix.name
            packet_bounds, packet_count = _pcap_packet_info(path)
            if packet_bounds is not None:
                capture_started_at, capture_finished_at = packet_bounds
                duration_seconds = max(0, int((capture_finished_at - capture_started_at).total_seconds()))
            elif exact_process_file:
                capture_started_at, capture_finished_at = started_at, finished_at
                duration_seconds = max(0, int((finished_at - started_at).total_seconds()))
            else:
                capture_started_at = capture_finished_at = None
                duration_seconds = None
            metadata = {
                "file_id": path.name,
                "capture_started_at": capture_started_at.isoformat() if capture_started_at else None,
                "capture_finished_at": capture_finished_at.isoformat() if capture_finished_at else None,
                "duration_seconds": duration_seconds,
                "original_size_bytes": size_bytes,
                "interface": self.interface,
                "snaplen": self.snaplen,
                "packet_count": packet_count,
                "sha256": None,
                "hash_status": "pending",
            }
            try:
                self._write_json_atomic(metadata_path, metadata)
            except OSError as exc:
                with self._lock:
                    self._last_error = f"Could not save PCAP metadata: {exc}"
                continue
            if self.compression != "none":
                self._queue_compression(path)
                with self._lock:
                    queued_for_compression = path.name in self._compressing
                if not queued_for_compression:
                    self._queue_hash(path, path.name)
            else:
                self._queue_hash(path, path.name)

    def _ensure_compressor(self) -> None:
        with self._lock:
            if self._compression_thread and self._compression_thread.is_alive():
                return
            self._compression_thread = threading.Thread(
                target=self._compress_loop, name="palantir-pcap-compressor", daemon=True
            )
            self._compression_thread.start()

    def _ensure_hash_worker(self) -> None:
        with self._lock:
            if self._hash_thread and self._hash_thread.is_alive():
                return
            self._hash_thread = threading.Thread(
                target=self._hash_loop, name="palantir-pcap-hasher", daemon=True
            )
            self._hash_thread.start()

    def _queue_hash(self, path: Path, file_id: str) -> None:
        self._ensure_hash_worker()
        try:
            self._hash_queue.put_nowait((path, file_id))
        except queue.Full:
            try:
                metadata_path = self._metadata_path(file_id)
                metadata = json.loads(metadata_path.read_text())
                metadata["hash_status"] = "queue_full"
                self._write_json_atomic(metadata_path, metadata)
            except (OSError, ValueError, TypeError):
                pass
            with self._lock:
                self._last_error = "PCAP hash queue is full; a file digest is pending"

    def _hash_loop(self) -> None:
        while True:
            item = self._hash_queue.get()
            try:
                if item is None:
                    return
                self._hash_one(*item)
            finally:
                self._hash_queue.task_done()

    def _hash_one(self, path: Path, file_id: str) -> None:
        try:
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            metadata_path = self._metadata_path(file_id)
            metadata = json.loads(metadata_path.read_text())
            metadata.update(sha256=digest.hexdigest(), hash_status="complete", stored_size_bytes=size)
            metadata["stored_filename"] = path.name
            self._write_json_atomic(metadata_path, metadata)
        except FileNotFoundError:
            try:
                metadata_path = self._metadata_path(file_id)
                metadata = json.loads(metadata_path.read_text())
                metadata.update(sha256=None, hash_status="unavailable")
                self._write_json_atomic(metadata_path, metadata)
            except (OSError, ValueError, TypeError):
                pass
        except (OSError, ValueError, TypeError) as exc:
            with self._lock:
                self._last_error = f"Could not hash PCAP file {file_id}: {exc}"

    def _queue_compression(self, path: Path) -> None:
        if not path.exists() or self.compression == "none":
            return
        if self.compression == "zstd" and shutil.which("zstd") is None:
            with self._lock:
                self._last_error = "zstd compression requested but zstd is not installed"
            return
        file_id = path.name
        with self._lock:
            if file_id in self._compressing:
                return
            self._compressing.add(file_id)
        try:
            self._compression_queue.put_nowait(path)
        except queue.Full:
            with self._lock:
                self._compressing.discard(file_id)
                self._last_error = "PCAP compression queue is full; retaining the uncompressed file"

    def _compress_loop(self) -> None:
        while True:
            path = self._compression_queue.get()
            try:
                if path is None:
                    return
                self._compress_one(path)
            finally:
                self._compression_queue.task_done()

    def _compress_one(self, path: Path) -> None:
        file_id = path.name
        suffix = ".zst" if self.compression == "zstd" else ".gz"
        output = Path(f"{path}{suffix}")
        temporary = Path(f"{output}.partial")
        try:
            if not path.is_file():
                return
            with temporary.open("wb") as target:
                if self.compression == "gzip":
                    with path.open("rb") as source, gzip.GzipFile(fileobj=target, mode="wb", compresslevel=1, mtime=0) as zipped:
                        shutil.copyfileobj(source, zipped, length=1024 * 1024)
                else:
                    result = subprocess.run(
                        ["zstd", "-1", "-q", "-c", str(path)],
                        stdout=target,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    if result.returncode != 0:
                        raise PCapError(f"zstd exited with status {result.returncode}")
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, output)
            path.unlink(missing_ok=True)
            self._queue_hash(output, file_id)
        except (OSError, PCapError) as exc:
            temporary.unlink(missing_ok=True)
            with self._lock:
                self._last_error = f"PCAP compression failed for {file_id}: {exc}"
            # Keep the raw capture transferrable if compression failed.
            if path.is_file():
                self._queue_hash(path, file_id)
        finally:
            with self._lock:
                self._compressing.discard(file_id)
        self._prune()

    def _artifact_paths(self, file_id: str) -> tuple[Path, Path]:
        raw = self.storage_dir / file_id
        if self.compression == "zstd":
            preferred = Path(f"{raw}.zst")
        elif self.compression == "gzip":
            preferred = Path(f"{raw}.gz")
        else:
            preferred = raw
        existing_compressed = []
        for candidate in (Path(f"{raw}.zst"), Path(f"{raw}.gz")):
            try:
                if candidate.is_file():
                    existing_compressed.append((candidate.stat().st_mtime, candidate))
            except OSError:
                continue
        compressed = max(existing_compressed, default=(0.0, preferred), key=lambda item: item[0])[1]
        return raw, compressed

    def _pin(self, snapshot_id: str, file_ids: list[str], expires_at: datetime) -> bool:
        self._expire_pins()
        with self._lock:
            if len(self._pins) >= self.max_active_snapshots:
                self._last_error = "PCAP snapshot limit reached; waiting for an earlier evidence transfer to finish"
                return False
        record = {"snapshot_id": snapshot_id, "file_ids": file_ids, "expires_at": expires_at.isoformat()}
        try:
            self._write_json_atomic(self._pins_dir / f"{snapshot_id}.json", record)
        except OSError as exc:
            with self._lock:
                self._last_error = f"Could not persist PCAP snapshot pin: {exc}"
            return False
        with self._lock:
            self._pins[snapshot_id] = record
        return True

    def _load_pins(self) -> None:
        try:
            for path in self._pins_dir.glob("[0-9a-f]" * 32 + ".json"):
                record = json.loads(path.read_text())
                snapshot_id = record.get("snapshot_id")
                expires_at = datetime.fromisoformat(record.get("expires_at", ""))
                file_ids = record.get("file_ids")
                if (
                    isinstance(snapshot_id, str) and re.fullmatch(r"[0-9a-f]{32}", snapshot_id)
                    and expires_at > datetime.now(timezone.utc)
                    and isinstance(file_ids, list)
                    and all(isinstance(item, str) and _FILE_ID.fullmatch(item) for item in file_ids)
                ):
                    self._pins[snapshot_id] = record
                else:
                    path.unlink(missing_ok=True)
        except OSError:
            pass
        except (ValueError, TypeError, json.JSONDecodeError):
            pass

    def _recover_closed_files(self) -> None:
        """Keep completed captures from a previous collector process usable."""
        for path in self.storage_dir.glob("capture_*.pcap*"):
            if not path.is_file() or not _FILE_ID.fullmatch(path.name):
                continue
            metadata_path = self._metadata_path(path.name)
            if not metadata_path.exists():
                match = re.match(r"^capture_(\d{8}T\d{6}Z)_", path.name)
                try:
                    started_at = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc) if match else datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                    finished_at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                    packet_bounds, packet_count = _pcap_packet_info(path)
                    if packet_bounds is not None:
                        started_at, finished_at = packet_bounds
                    self._write_json_atomic(metadata_path, {
                        "file_id": path.name,
                        "capture_started_at": started_at.isoformat(),
                        "capture_finished_at": finished_at.isoformat(),
                        "duration_seconds": max(0, int((finished_at - started_at).total_seconds())),
                        "original_size_bytes": path.stat().st_size,
                        "interface": self.interface,
                        "snaplen": self.snaplen,
                        "packet_count": packet_count,
                        "sha256": None,
                        "hash_status": "pending",
                    })
                except OSError:
                    continue
            if path.suffix not in {".zst", ".gz"} and self.compression != "none":
                self._queue_compression(path)
            else:
                try:
                    metadata = json.loads(metadata_path.read_text())
                    if not metadata.get("sha256"):
                        self._queue_hash(path, metadata["file_id"])
                except (OSError, ValueError, TypeError, KeyError):
                    continue

    def _expire_pins(self) -> None:
        now = datetime.now(timezone.utc)
        expired: list[str] = []
        with self._lock:
            for snapshot_id, pin in self._pins.items():
                try:
                    if datetime.fromisoformat(pin["expires_at"]) <= now:
                        expired.append(snapshot_id)
                except (KeyError, TypeError, ValueError):
                    expired.append(snapshot_id)
        for snapshot_id in expired:
            self.release_snapshot(snapshot_id)

    def _prune(self) -> None:
        self._expire_pins_without_pruning()
        with self._lock:
            pinned = {
                file_id
                for record in self._pins.values()
                for file_id in record.get("file_ids", [])
            }
            compressing = set(self._compressing)
        records: list[tuple[float, str, int]] = []
        for path in self.storage_dir.glob("capture_*.pcap*.json"):
            try:
                record = json.loads(path.read_text())
                file_id = record.get("file_id")
                if isinstance(file_id, str) and _FILE_ID.fullmatch(file_id):
                    raw_path, final_path = self._artifact_paths(file_id)
                    artifact = final_path if final_path.exists() else raw_path
                    records.append((path.stat().st_mtime, file_id, artifact.stat().st_size if artifact.exists() else 0))
            except (OSError, ValueError, TypeError):
                continue
        records.sort(reverse=True)
        keep = {file_id for _, file_id, _ in records[:self.max_files]} | pinned
        for _, file_id, _ in records:
            if file_id in keep or file_id in compressing:
                continue
            self._delete_artifact(file_id)
        retained = [record for record in records if record[1] in keep]
        total_bytes = sum(size for _, _, size in retained)
        for _, file_id, size in reversed(retained):
            if total_bytes <= self.max_total_bytes:
                break
            if file_id in pinned or file_id in compressing:
                continue
            self._delete_artifact(file_id)
            keep.discard(file_id)
            total_bytes -= size

    def _expire_pins_without_pruning(self) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            expired = []
            for snapshot_id, record in self._pins.items():
                try:
                    if datetime.fromisoformat(record["expires_at"]) <= now:
                        expired.append(snapshot_id)
                except (KeyError, TypeError, ValueError):
                    expired.append(snapshot_id)
            for snapshot_id in expired:
                self._pins.pop(snapshot_id, None)
                try:
                    (self._pins_dir / f"{snapshot_id}.json").unlink(missing_ok=True)
                except OSError:
                    pass

    def _delete_artifact(self, file_id: str) -> None:
        raw_path = self.storage_dir / file_id
        existed = any(path.exists() for path in (
            raw_path, Path(f"{raw_path}.zst"), Path(f"{raw_path}.gz"),
        ))
        for path in (
            raw_path,
            Path(f"{raw_path}.zst"),
            Path(f"{raw_path}.gz"),
            Path(f"{raw_path}.zst.partial"),
            Path(f"{raw_path}.gz.partial"),
            self._metadata_path(file_id),
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if existed:
            with self._lock:
                self._dropped_files += 1

    def _coverage_seconds(self, files: list[dict[str, Any]]) -> int:
        starts = []
        finishes = []
        for item in files:
            try:
                started = datetime.fromisoformat(item["capture_started_at"])
                finished = datetime.fromisoformat(item["capture_finished_at"])
            except (KeyError, TypeError, ValueError):
                continue
            starts.append(started)
            finishes.append(finished)
        if not starts or not finishes:
            return 0
        return max(0, int((max(finishes) - min(starts)).total_seconds()))

    @staticmethod
    def _file_recency(item: dict[str, Any]) -> float:
        for key in ("capture_finished_at", "capture_started_at"):
            value = item.get(key)
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    pass
        file_id = item.get("file_id", "")
        match = re.match(r"^capture_(\d{8}T\d{6}Z)_", file_id)
        if match:
            try:
                return datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                pass
        return 0.0

    def _metadata_path(self, file_id: str) -> Path:
        return self.storage_dir / f"{file_id}.json"

    @staticmethod
    def _normalize_compression_label(value: str | None) -> str:
        if not value:
            return "none"
        return _COMPRESSION_ALIASES.get(value, "none")

    def _await_files_transfer_ready(self, file_ids: list[str], timeout: float = 15.0) -> list[dict[str, Any]]:
        """Block until pinned files are ready with a complete digest, or timeout."""
        wanted = set(file_ids)
        if not wanted:
            return []
        deadline = time.monotonic() + max(0.1, timeout)
        last: list[dict[str, Any]] = []
        requeued: set[str] = set()
        while time.monotonic() < deadline:
            last = [item for item in self.files() if item.get("file_id") in wanted]
            by_id = {item["file_id"]: item for item in last}
            if all(
                (item := by_id.get(file_id)) is not None
                and item.get("status") == "ready"
                and item.get("hash_status") == "complete"
                and item.get("sha256")
                for file_id in wanted
            ):
                return [by_id[file_id] for file_id in file_ids if file_id in by_id]
            # Re-queue digests that stalled once compression finished.
            for file_id in wanted:
                if file_id in requeued:
                    continue
                item = by_id.get(file_id)
                if item is None or item.get("status") != "ready":
                    continue
                if item.get("hash_status") in {"pending", "queue_full"} and not item.get("sha256"):
                    raw_path, final_path = self._artifact_paths(file_id)
                    path = final_path if final_path.is_file() else raw_path
                    if path.is_file():
                        self._queue_hash(path, file_id)
                        requeued.add(file_id)
            time.sleep(0.05)
        # Prefer ready+hashed files; keep remaining entries so the caller still sees state.
        ready = [
            item for item in last
            if item.get("status") == "ready" and item.get("hash_status") == "complete" and item.get("sha256")
        ]
        if ready:
            return ready
        return last

    @staticmethod
    def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_suffix(path.suffix + ".partial")
        temporary.write_text(json.dumps(data, separators=(",", ":")))
        os.replace(temporary, path)

