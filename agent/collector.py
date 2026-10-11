"""Small Linux host collector exposed to the central pull worker."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import time
import glob
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
import httpx
from fastapi import FastAPI, Header, HTTPException, Query

APP_VERSION = "0.1.0"
HOST_PROC = Path(os.getenv("HOST_PROC", "/host/proc" if Path("/host/proc").exists() else "/proc"))
HOST_SYS = Path(os.getenv("HOST_SYS", "/host/sys" if Path("/host/sys").exists() else "/sys"))
HOST_ROOT = Path(os.getenv("HOST_ROOT", "/host" if Path("/host").exists() else "/"))
HOST_LOG = Path(os.getenv("HOST_LOG", "/host/var/log"))
AGENT_TOKEN = os.getenv("PALANTIR_AGENT_TOKEN", "")
LOG_MIN_PRIORITY = int(os.getenv("LOG_MIN_PRIORITY", "7"))
LOG_LIMIT_MAX = int(os.getenv("LOG_LIMIT_MAX", "5000"))
APP_LOG_GLOBS = [item for item in os.getenv("APP_LOG_GLOBS", "/host/var/log/**/*.log").split(",") if item]
def _first_socket(candidates: list[str], default: str) -> Path:
    """First candidate that is a live unix socket (blank candidates are skipped), else `default`."""
    for candidate in candidates:
        if candidate:
            path = Path(candidate)
            try:
                if path.exists() and path.is_socket():
                    return path
            except OSError:
                continue
    return Path(default)


# Docker and Podman (Podman exposes a Docker-compatible API), LXD / Incus, libvirt: first live socket wins.
DOCKER_SOCKET = _first_socket([
    os.getenv("DOCKER_SOCKET", ""), "/host/run/docker.sock", "/host/var/run/docker.sock", "/var/run/docker.sock",
    "/run/docker.sock", "/host/run/podman/podman.sock", "/run/podman/podman.sock",
], "/host/run/docker.sock")
LXD_SOCKET = _first_socket([
    os.getenv("LXD_SOCKET", ""), "/host/var/lib/lxd/unix.socket", "/host/var/snap/lxd/common/lxd/unix.socket",
    "/host/run/lxd/unix.socket", "/host/var/lib/incus/unix.socket", "/host/run/incus/unix.socket",
], "/host/var/lib/lxd/unix.socket")
LIBVIRT_SOCKET = _first_socket([
    os.getenv("LIBVIRT_SOCKET", ""), "/host/run/libvirt/libvirt-sock", "/host/run/libvirt/virtqemud-sock",
    "/run/libvirt/libvirt-sock", "/run/libvirt/virtqemud-sock",
], "/host/run/libvirt/libvirt-sock")
ALLOW_ANONYMOUS_KILL = os.getenv("PALANTIR_ALLOW_ANON_KILL", "") == "1"
PROXMOX_INSECURE_TLS = os.getenv("PROXMOX_INSECURE_TLS", "") == "1"  # Proxmox ships a self-signed certificate
KUBERNETES_API_URL = os.getenv("KUBERNETES_API_URL", "").rstrip("/")
KUBERNETES_TOKEN = os.getenv("KUBERNETES_TOKEN", "")
KUBERNETES_CA_CERT = os.getenv("KUBERNETES_CA_CERT", "")
PROXMOX_API_URL = os.getenv("PROXMOX_API_URL", "").rstrip("/")
PROXMOX_API_TOKEN = os.getenv("PROXMOX_API_TOKEN", "")
PROXMOX_CA_CERT = os.getenv("PROXMOX_CA_CERT", "")
LOG_STATE = Path(os.getenv("LOG_STATE", "/var/lib/palantir-agent/log-offsets.json"))
SENSITIVE_KEY = re.compile(r"password|passwd|token|secret|api[_-]?key|authorization|credential", re.IGNORECASE)
SENSITIVE_VALUE = re.compile(r"(?i)((?:password|passwd|token|secret|api[_-]?key|authorization)(?:\s*[:=]\s*))(?:bearer\s+)?(?:['\"])?[^\s,;'\"]+")
if HOST_PROC.exists():
    psutil.PROCFS_PATH = str(HOST_PROC)
_LOG_STATE_LOCK = threading.Lock()
try:
    _LOG_OFFSETS: dict[str, dict[str, int]] = json.loads(LOG_STATE.read_text())
except (OSError, json.JSONDecodeError):
    _LOG_OFFSETS = {}


app = FastAPI(title="PALANTIR Linux Host Collector", version=APP_VERSION)

CATEGORIES = ("system", "storage", "network", "services", "processes", "connections", "containers", "vms")

# --------------------------------------------------------------------------------------
# Sampling configuration (all optional environment variables)
# --------------------------------------------------------------------------------------
# CPU is sampled continuously (default every 1 s) from /proc/stat deltas.  Every number the
# API reports for CPU (total, per core, user/system/iowait split, per-second history) comes
# from these same samples, so they always agree with each other and with tools such as the
# GNOME System Monitor / top / htop, which also use 1 s deltas.  Nothing is ever measured
# over a tiny ad-hoc window at request time (that is what produced spurious 100 % cores).
CPU_SAMPLE_INTERVAL = max(0.5, float(os.getenv("CPU_SAMPLE_INTERVAL", "1")))   # seconds between CPU samples
CPU_SAMPLE_BUFFER = max(60, int(os.getenv("CPU_SAMPLE_BUFFER", "900")))        # samples kept in memory (15 min @ 1 s)
CPU_CURRENT_WINDOW = max(1, int(os.getenv("CPU_CURRENT_WINDOW", "5")))         # samples averaged for "current" CPU
RATE_SAMPLE_SECONDS = max(2.0, float(os.getenv("RATE_SAMPLE_SECONDS", "5")))   # process / network / disk rates
PID_REUSE_TOLERANCE_SECONDS = 5.0                                              # create_time jitter vs. PID reuse

_CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_text(path: Path, limit: int = 2_000_000) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            return stream.read(limit)
    except (OSError, PermissionError):
        return ""


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _read_cpu_stat() -> dict[str, tuple[float, ...]] | None:
    """Cumulative CPU time counters: {"cpu": (...), "cpu0": (...), ...} or None when unreadable."""
    counters: dict[str, tuple[float, ...]] = {}
    for line in _read_text(HOST_PROC / "stat", 1_000_000).splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        name = parts[0]
        if name != "cpu" and not name[3:].isdigit():
            continue
        try:
            values = [float(item) for item in parts[1:9]]
        except ValueError:
            continue
        if len(values) < 8:
            values += [0.0] * (8 - len(values))
        counters[name] = tuple(values)
    if "cpu" in counters:
        return counters
    # /proc/stat unreadable: fall back to psutil (it reads the same counters)
    try:
        total = psutil.cpu_times()
        per_core = psutil.cpu_times(percpu=True)
    except Exception:
        return None
    pick = lambda item: tuple(float(getattr(item, field, 0.0) or 0.0) for field in _CPU_FIELDS)  # noqa: E731
    counters = {"cpu": pick(total)}
    for index, item in enumerate(per_core):
        counters[f"cpu{index}"] = pick(item)
    return counters


def _cpu_delta(previous: tuple[float, ...], current: tuple[float, ...]) -> dict[str, float] | None:
    """Percentages for one interval, or None if the counters went backwards / nothing elapsed."""
    delta = [now - before for now, before in zip(current, previous)]
    if any(item < 0 for item in delta):
        return None  # counter reset or CPU hot-plug
    user, nice, system, idle, iowait, irq, softirq, steal = delta
    total = user + nice + system + idle + iowait + irq + softirq + steal
    if total <= 0:
        return None
    busy = total - idle - iowait  # iowait is time the CPU could not do anything else: idle, like top/psutil

    def pct(value: float) -> float:
        return round(max(0.0, min(100.0, value * 100.0 / total)), 2)

    return {
        "cpu_pct": pct(busy),
        "user": pct(user), "nice": pct(nice), "system": pct(system), "idle": pct(idle),
        "iowait": pct(iowait), "irq": pct(irq), "softirq": pct(softirq), "steal": pct(steal),
    }


def _note_sampler_error(sampler: Any, name: str, exc: Exception) -> None:
    message = f"{type(exc).__name__}: {exc}"
    if sampler.last_error != message:  # log each distinct failure once, not every second
        print(f"[palantir-collector] {name} sampler error: {message}", flush=True)
    sampler.last_error = message


class _CpuSampler:
    """Background thread: one timestamped CPU sample per interval, kept in a ring buffer."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._samples: deque[dict[str, Any]] = deque(maxlen=CPU_SAMPLE_BUFFER)
        self._previous: dict[str, tuple[float, ...]] | None = None
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="palantir-cpu-sampler", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        next_tick = time.monotonic()
        while True:
            try:
                self.tick()
                self.last_error = None
            except Exception as exc:
                _note_sampler_error(self, "cpu", exc)
            next_tick += CPU_SAMPLE_INTERVAL
            delay = next_tick - time.monotonic()
            if delay < -10 * CPU_SAMPLE_INTERVAL:  # the host was suspended / we fell far behind: re-sync
                next_tick = time.monotonic()
                delay = 0.0
            time.sleep(max(0.0, delay))

    def tick(self) -> dict[str, Any] | None:
        current = _read_cpu_stat()
        stamp = time.time()
        if current is None:
            self._previous = None
            return None
        previous, self._previous = self._previous, current
        if previous is None or "cpu" not in previous:
            return None
        total = _cpu_delta(previous["cpu"], current["cpu"])
        if total is None:
            return None
        cores: list[float | None] = []
        for name in sorted((key for key in current if key != "cpu"), key=lambda key: int(key[3:])):
            stats = _cpu_delta(previous[name], current[name]) if name in previous else None
            cores.append(stats["cpu_pct"] if stats else None)
        sample = {
            "t": round(stamp, 3),
            "cpu_pct": total["cpu_pct"],
            "cores": cores,
            "times": {key: value for key, value in total.items() if key != "cpu_pct"},
        }
        with self._lock:
            self._samples.append(sample)
        return sample

    # ---- readers -------------------------------------------------------------------------
    def current(self, window: int = CPU_CURRENT_WINDOW) -> dict[str, Any] | None:
        """Mean of the last `window` samples, or None when sampling is not producing fresh data."""
        with self._lock:
            recent = list(self._samples)[-max(1, window):]
        if not recent:
            return None
        if time.time() - recent[-1]["t"] > max(5.0, 4 * CPU_SAMPLE_INTERVAL):
            return None  # sampler stalled: report "no data" instead of a stale number
        cores: list[float] = []
        width = max(len(sample["cores"]) for sample in recent)
        for index in range(width):
            values = [s["cores"][index] for s in recent if index < len(s["cores"]) and s["cores"][index] is not None]
            if values:
                cores.append(round(sum(values) / len(values), 2))
        times = {key: round(_mean([s["times"][key] for s in recent]) or 0.0, 2) for key in recent[-1]["times"]}
        return {
            "cpu_pct": round(_mean([s["cpu_pct"] for s in recent]) or 0.0, 2),
            "cores": cores,
            "times": times,
            "window_samples": len(recent),
            "t": recent[-1]["t"],
        }

    def history(self, count: int = 60) -> list[float]:
        with self._lock:
            return [sample["cpu_pct"] for sample in list(self._samples)[-count:]]

    def count(self) -> int:
        with self._lock:
            return len(self._samples)

    def since(self, since: float, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            fresh = [sample for sample in self._samples if sample["t"] > since]
        return [{"t": sample["t"], "cpu_pct": sample["cpu_pct"]} for sample in fresh[-limit:]]


class _RateSampler:
    """Background thread: per-process CPU %, per-interface network and per-disk I/O *rates*.

    Every rate is a counter delta divided by the real elapsed time between two reads, so a
    value is only reported once two reads exist.  Unknown stays None - it is never guessed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        # pid -> (create_time, cpu_seconds) / pid -> (create_time, % of one core)
        self._proc_prev: dict[int, tuple[float, float]] = {}
        self._proc_rates: dict[int, tuple[float, float]] = {}
        self._net_prev: dict[str, dict[str, int]] = {}
        self._net_rates: dict[str, dict[str, float]] = {}
        self._disk_prev: dict[str, Any] = {}
        self._disk_rates: dict[str, dict[str, float]] = {}
        self._last_ts: float | None = None
        self._updated_at: float | None = None
        self.last_error: str | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="palantir-rate-sampler", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        next_tick = time.monotonic()
        while True:
            try:
                self.tick()
                self.last_error = None
            except Exception as exc:
                _note_sampler_error(self, "rate", exc)
            next_tick += RATE_SAMPLE_SECONDS
            delay = next_tick - time.monotonic()
            if delay < -10 * RATE_SAMPLE_SECONDS:
                next_tick = time.monotonic()
                delay = 0.0
            time.sleep(max(0.0, delay))

    def tick(self) -> None:
        stamp = time.monotonic()
        wall = time.time()
        proc_now: dict[int, tuple[float, float]] = {}
        for proc in psutil.process_iter(attrs=["pid", "cpu_times", "create_time"]):
            info = proc.info
            times = info.get("cpu_times")
            created = info.get("create_time")
            if times is None or created is None:
                continue
            proc_now[info["pid"]] = (float(created), float(times.user + times.system))
        net_now = _parse_proc_net_dev()
        try:
            disk_now = psutil.disk_io_counters(perdisk=True, nowrap=True) or {}
        except (OSError, RuntimeError):
            disk_now = {}

        with self._lock:
            elapsed = (stamp - self._last_ts) if self._last_ts is not None else None
            if elapsed and elapsed > 0.5:
                proc_rates: dict[int, tuple[float, float]] = {}
                for pid, (created, cpu_seconds) in proc_now.items():
                    previous = self._proc_prev.get(pid)
                    if previous is None:
                        continue  # appeared since the last read: genuinely not measurable yet
                    # create_time is derived from the boot time and drifts by a fraction of a second between
                    # reads, so it must be compared with a tolerance - an exact match silently dropped
                    # real processes.  A different start time means the PID was reused: skip it.
                    if abs(created - previous[0]) > PID_REUSE_TOLERANCE_SECONDS or cpu_seconds < previous[1]:
                        continue
                    proc_rates[pid] = (created, (cpu_seconds - previous[1]) * 100.0 / elapsed)  # % of ONE core
                net_rates: dict[str, dict[str, float]] = {}
                for name, counters in net_now.items():
                    before = self._net_prev.get(name)
                    if not before:
                        continue
                    rates: dict[str, float] = {}
                    for label, key in (("rx_bytes_per_sec", "bytes_recv"), ("tx_bytes_per_sec", "bytes_sent"),
                                       ("rx_packets_per_sec", "packets_recv"), ("tx_packets_per_sec", "packets_sent")):
                        change = counters.get(key, 0) - before.get(key, 0)
                        if change >= 0:  # negative = counter reset (reboot / interface re-created)
                            rates[label] = round(change / elapsed, 2)
                    if rates:
                        net_rates[name] = rates
                disk_rates: dict[str, dict[str, float]] = {}
                for name, counters in disk_now.items():
                    before = self._disk_prev.get(name)
                    if before is None:
                        continue
                    rates = {}
                    for label, attribute in (("read_bytes_per_sec", "read_bytes"), ("write_bytes_per_sec", "write_bytes"),
                                             ("read_iops", "read_count"), ("write_iops", "write_count")):
                        change = getattr(counters, attribute, 0) - getattr(before, attribute, 0)
                        if change >= 0:
                            rates[label] = round(change / elapsed, 2)
                    busy_now = getattr(counters, "busy_time", None)
                    busy_before = getattr(before, "busy_time", None)
                    if busy_now is not None and busy_before is not None:
                        busy_ms_diff = busy_now - busy_before
                        if busy_ms_diff >= 0 and elapsed > 0:
                            rates["busy_pct"] = round(min(100.0, (busy_ms_diff / (elapsed * 1000.0)) * 100.0), 1)
                    if rates:
                        disk_rates[name] = rates
                self._proc_rates, self._net_rates, self._disk_rates = proc_rates, net_rates, disk_rates
                self._updated_at = wall
            self._proc_prev, self._net_prev, self._disk_prev, self._last_ts = proc_now, net_now, dict(disk_now), stamp

    def fresh(self) -> bool:
        return self._updated_at is not None and time.time() - self._updated_at <= max(30.0, 4 * RATE_SAMPLE_SECONDS)

    def process_rates(self) -> dict[int, tuple[float, float]]:
        with self._lock:
            return dict(self._proc_rates) if self.fresh() else {}

    def network_rates(self) -> dict[str, dict[str, float]]:
        with self._lock:
            return {name: dict(rates) for name, rates in self._net_rates.items()} if self.fresh() else {}

    def disk_rates(self) -> dict[str, dict[str, float]]:
        with self._lock:
            return {name: dict(rates) for name, rates in self._disk_rates.items()} if self.fresh() else {}


_CPU_SAMPLER = _CpuSampler()
_RATE_SAMPLER = _RateSampler()


def _start_samplers() -> None:
    _CPU_SAMPLER.start()
    _RATE_SAMPLER.start()


def _redact_text(value: str) -> str:
    return SENSITIVE_VALUE.sub(r"\1[REDACTED]", value)


def _safe_fields(fields: dict[str, Any]) -> dict[str, Any]:
    safe = {}
    for key, value in fields.items():
        if SENSITIVE_KEY.search(key):
            safe[key] = "[REDACTED]"
        elif isinstance(value, dict):
            safe[key] = _safe_fields(value)
        elif isinstance(value, list):
            safe[key] = [
                _safe_fields(item) if isinstance(item, dict)
                else _redact_text(item) if isinstance(item, str)
                else item
                for item in value
            ]
        elif isinstance(value, str):
            safe[key] = _redact_text(value)
        else:
            safe[key] = value
    return safe


def _guard(token: str | None) -> None:
    if AGENT_TOKEN and not (token and hmac.compare_digest(token.encode(), AGENT_TOKEN.encode())):
        raise HTTPException(status_code=403, detail="Invalid agent token")


def _status_data(data: Any, capability: str = "available") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "observed_at": _now(),
        "status": capability,
        "data": data,
    }


def _proc_mount_path(mountpoint: str) -> Path:
    relative = mountpoint.lstrip("/")
    return HOST_ROOT / relative


def _disk_io() -> list[dict[str, Any]]:
    try:
        stats = psutil.disk_io_counters(perdisk=True, nowrap=True)
    except (OSError, RuntimeError):
        stats = None
    rates = _RATE_SAMPLER.disk_rates()
    rows = []
    for name, item in sorted((stats or {}).items()):
        row = {
            "device": name,
            "read_bytes": item.read_bytes,
            "write_bytes": item.write_bytes,
            "read_count": item.read_count,
            "write_count": item.write_count,
            "read_time_ms": item.read_time,
            "write_time_ms": item.write_time,
        }
        row.update(rates.get(name, {}))  # *_per_sec / *_iops, only present when measured
        rows.append(row)
    return rows


def _parse_mdstat(mdstat: str) -> list[dict[str, Any]]:
    arrays: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in mdstat.splitlines():
        header = re.match(r"^(md\d+)\s*:\s*(\w+)\s*(.*)$", line)
        if header:
            current = {
                "name": header.group(1),
                "state": header.group(2),
                "level": next((part for part in header.group(3).split() if part.startswith("raid")), None),
                "devices": [],
                "active_devices": None,
                "total_devices": None,
                "degraded": None,
                "sync": None,
            }
            current["devices"] = [
                {"name": device, "slot": int(slot), "failed": failed == "F"}
                for device, slot, failed in re.findall(r"([^\s\[\]]+)\[(\d+)\](?:\(([A-Z])\))?", header.group(3))
            ]
            arrays.append(current)
            continue
        if current is None:
            continue
        count_match = re.search(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]", line)
        if count_match:
            current["active_devices"] = int(count_match.group(1))
            current["total_devices"] = int(count_match.group(2))
            current["degraded"] = "_" in count_match.group(3) or count_match.group(1) != count_match.group(2)
        sync_match = re.search(r"(resync|recovery|reshape|check)\s*=\s*([\d.]+)%", line)
        if sync_match:
            current["sync"] = {"operation": sync_match.group(1), "percent": float(sync_match.group(2))}
    return arrays


def _read_loadavg() -> list[float]:
    """1/5/15 minute load averages from the HOST's /proc/loadavg (empty list when unavailable)."""
    parts = _read_text(HOST_PROC / "loadavg", 512).split()
    try:
        return [float(item) for item in parts[:3]] if len(parts) >= 3 else []
    except ValueError:
        return []


_CPU_MODEL_CACHE: list[str | None] = []


def _cpu_model() -> str | None:
    if _CPU_MODEL_CACHE:
        return _CPU_MODEL_CACHE[0]
    found: dict[str, str] = {}
    for line in _read_text(HOST_PROC / "cpuinfo", 1_000_000).splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), re.sub(r"\s+", " ", value.strip())
        if value and key in {"model name", "hardware", "model", "cpu model"} and key not in found:
            found[key] = value
    # x86 reports the marketing name in "model name"; a bare "model" there is a numeric id, ARM boards use Hardware/Model.
    model = found.get("model name") or found.get("hardware") or found.get("cpu model")
    if model is None and found.get("model") and not found["model"].isdigit():
        model = found["model"]
    _CPU_MODEL_CACHE.append(model)
    return model


def _read_os_release() -> dict[str, str]:
    for os_file in (HOST_ROOT / "etc/os-release", HOST_ROOT / "usr/lib/os-release", Path("/etc/os-release"), Path("/usr/lib/os-release")):
        text = _read_text(os_file, 16_000)
        if not text:
            continue
        values: dict[str, str] = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"')
        if values.get("ID") or values.get("NAME"):
            return values
    return {}


def _read_first_line(path: Path, limit: int = 512) -> str | None:
    text = _read_text(path, limit).strip()
    return text.splitlines()[0].strip() if text else None


def _host_hostname() -> str:
    """The HOST's name.  Inside a container socket.gethostname() is the container id, so prefer /etc/hostname."""
    for path in (HOST_ROOT / "etc/hostname", Path("/etc/hostname")):
        name = _read_first_line(path, 256)
        if name:
            return name
    return socket.gethostname()


def _host_machine_id() -> str:
    """Unique persistent machine ID for this OS / VM / bare-metal host."""
    for path in (
        HOST_ROOT / "etc/machine-id",
        Path("/etc/machine-id"),
        HOST_ROOT / "var/lib/dbus/machine-id",
        Path("/var/lib/dbus/machine-id"),
    ):
        val = _read_first_line(path, 128)
        if val and len(val) >= 16:
            return val.strip().lower()

    dmi_uuid = _read_first_line(HOST_SYS / "class/dmi/id/product_uuid", 128)
    if dmi_uuid and len(dmi_uuid) >= 16:
        return dmi_uuid.strip().lower()

    # Fallback to persistent primary interface MAC address
    try:
        import uuid
        mac = uuid.getnode()
        if (mac >> 40) % 2 == 0:  # Valid non-random MAC
            return f"mac-{mac:012x}"
    except Exception:
        pass

    return f"host-{_host_hostname()}"



_VIRT_MARKERS = (
    ("kvm", "KVM"), ("qemu", "QEMU/KVM"), ("vmware", "VMware"), ("virtualbox", "VirtualBox"), ("innotek", "VirtualBox"),
    ("xen", "Xen"), ("hyper-v", "Hyper-V"), ("virtual machine", "Hyper-V"), ("amazon ec2", "AWS EC2 (Nitro/KVM)"),
    ("google compute", "Google Compute Engine"), ("digitalocean", "DigitalOcean"), ("openstack", "OpenStack"),
    ("parallels", "Parallels"), ("bochs", "Bochs"), ("bhyve", "bhyve"), ("proxmox", "Proxmox/KVM"),
)


def _virtualization() -> dict[str, Any]:
    """Is this machine itself a virtual machine (and on what)?  is_virtual is None when it cannot be told."""
    cpuinfo = _read_text(HOST_PROC / "cpuinfo", 1_000_000)
    flags_line = next((line for line in cpuinfo.splitlines() if line.lower().startswith(("flags", "features"))), "")
    dmi = HOST_SYS / "class/dmi/id"
    vendor = _read_first_line(dmi / "sys_vendor")
    product = _read_first_line(dmi / "product_name")
    haystack = f"{vendor or ''} {product or ''}".lower()
    hypervisor = next((label for marker, label in _VIRT_MARKERS if marker in haystack), None)
    flagged = " hypervisor" in f" {flags_line}"
    if flagged or hypervisor:
        return {"is_virtual": True, "hypervisor": hypervisor, "vendor": vendor, "product": product}
    if cpuinfo:
        return {"is_virtual": False, "hypervisor": None, "vendor": vendor, "product": product}
    return {"is_virtual": None, "hypervisor": None, "vendor": vendor, "product": product}


def _temperatures() -> list[dict[str, Any]]:
    readings: list[dict[str, Any]] = []
    base = HOST_SYS / "class/hwmon"
    try:
        chips = sorted(base.iterdir())
    except OSError:
        return readings
    for chip in chips:
        chip_name = _read_first_line(chip / "name") or chip.name
        try:
            inputs = sorted(item for item in chip.iterdir() if re.fullmatch(r"temp\d+_input", item.name))
        except OSError:
            continue
        for item in inputs:
            raw = _read_first_line(item, 32)
            try:
                celsius = int(raw) / 1000.0 if raw is not None else None
            except ValueError:
                celsius = None
            if celsius is None or not -60.0 <= celsius <= 200.0:
                continue  # unplugged / broken sensor
            readings.append({"sensor": chip_name, "label": _read_first_line(chip / item.name.replace("_input", "_label")) or item.name.replace("_input", ""), "celsius": round(celsius, 1)})
        if len(readings) >= 60:
            break
    return readings[:60]


def _batteries() -> list[dict[str, Any]]:
    batteries: list[dict[str, Any]] = []
    try:
        supplies = sorted((HOST_SYS / "class/power_supply").iterdir())
    except OSError:
        return batteries
    for supply in supplies:
        if _read_first_line(supply / "type") != "Battery":
            continue
        capacity = _read_first_line(supply / "capacity", 16)
        batteries.append({"name": supply.name, "percent": int(capacity) if capacity and capacity.isdigit() else None, "status": _read_first_line(supply / "status", 32)})
    return batteries


def _uptime_seconds() -> float | None:
    first = _read_first_line(HOST_PROC / "uptime", 128)
    try:
        return round(float(first.split()[0]), 1) if first else None
    except (ValueError, IndexError):
        return None


def collect_system() -> dict[str, Any]:
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    cpu = _CPU_SAMPLER.current()

    vmstat: dict[str, int] = {}
    for line in _read_text(HOST_PROC / "vmstat", 256_000).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in {"oom_kill", "pgmajfault", "pswpin", "pswpout"}:
            try:
                vmstat[parts[0]] = int(parts[1])
            except ValueError:
                pass

    meminfo: dict[str, int] = {}
    for line in _read_text(HOST_PROC / "meminfo", 256_000).splitlines():
        key, _, rest = line.partition(":")
        fields = rest.split()
        if fields and fields[0].isdigit():
            meminfo[key.strip()] = int(fields[0]) * 1024  # kB -> bytes

    logical = len(cpu["cores"]) if cpu and cpu["cores"] else (psutil.cpu_count(logical=True) or None)
    physical = psutil.cpu_count(logical=False) or logical

    data = {
        "cpu_count": physical,
        "cpu_logical_count": logical,
        "cpu_model": _cpu_model(),
        # Current CPU = mean of the last few 1-second samples. None (not 0) when unavailable.
        "cpu_pct": cpu["cpu_pct"] if cpu else None,
        "cpu_cores_pct": cpu["cores"] if cpu else [],
        "cpu_times": cpu["times"] if cpu else {},
        "cpu_window_seconds": round(cpu["window_samples"] * CPU_SAMPLE_INTERVAL, 1) if cpu else None,
        # last 60 one-second samples, oldest first
        "cpu_history": _CPU_SAMPLER.history(60),
        "cpu_history_interval_seconds": CPU_SAMPLE_INTERVAL,
        "memory": {
            "total_bytes": mem.total,
            "available_bytes": mem.available,
            "used_bytes": mem.used,  # total - available, i.e. what is really in use
            "free_bytes": mem.free,
            "buffers_bytes": getattr(mem, "buffers", meminfo.get("Buffers")),
            "cached_bytes": getattr(mem, "cached", meminfo.get("Cached")),
            "active_bytes": getattr(mem, "active", meminfo.get("Active")),
            "inactive_bytes": getattr(mem, "inactive", meminfo.get("Inactive")),
            "slab_bytes": getattr(mem, "slab", meminfo.get("Slab")),
            "percent": mem.percent,
        },
        "swap": {
            "total_bytes": swap.total,
            "used_bytes": swap.used,
            "percent": swap.percent if swap.total else None,  # no swap configured -> no percentage
        },
        "load_average": _read_loadavg(),
        "hostname": _host_hostname(),
        "kernel": _read_first_line(HOST_PROC / "sys/kernel/osrelease", 128),
        "architecture": platform.machine(),
        "uptime_seconds": _uptime_seconds(),
        "virtualization": _virtualization(),
        "temperatures": _temperatures(),
        "batteries": _batteries(),
        "vmstat": vmstat,
        "os_release": _read_os_release(),
    }
    return _status_data(data, "available" if cpu else "partial")


_PSEUDO_FS = {
    "squashfs", "overlay", "tmpfs", "devtmpfs", "ramfs", "proc", "sysfs", "cgroup", "cgroup2", "binfmt_misc",
    "efivarfs", "bpf", "pstore", "fusectl", "configfs", "debugfs", "tracefs", "autofs", "devpts", "mqueue",
    "hugetlbfs", "securityfs", "selinuxfs", "nsfs", "rpc_pipefs", "fuse.gvfsd-fuse", "fuse.portal", "fuse.lxcfs",
    "iso9660", "udf", "aufs",
}
_NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "fuse.sshfs", "9p", "virtiofs"}
_SKIP_MOUNT_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/snap", "/var/lib/docker", "/var/lib/containers",
                        "/var/lib/kubelet", "/var/lib/lxd", "/var/lib/lxcfs")


def _unescape_mount(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _host_mounts() -> list[dict[str, str]]:
    """Mounted filesystems of the HOST (PID 1's mount namespace), not of this container."""
    for source in (HOST_PROC / "1/mounts", HOST_PROC / "mounts"):
        text = _read_text(source, 1_000_000)
        if text.strip():
            break
    else:
        text = ""
    mounts: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mounts.append({"device": _unescape_mount(parts[0]), "mountpoint": _unescape_mount(parts[1]), "filesystem": parts[2], "options": parts[3]})
    if mounts:
        return mounts
    try:
        return [{"device": p.device, "mountpoint": p.mountpoint, "filesystem": p.fstype, "options": p.opts}
                for p in psutil.disk_partitions(all=False)]
    except (OSError, RuntimeError):
        return []


def _block_devices() -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    try:
        entries = sorted((HOST_SYS / "block").iterdir())
    except OSError:
        return devices
    for entry in entries:
        if re.match(r"^(loop|ram|zram|fd|sr)\d*", entry.name):
            continue
        sectors = _read_first_line(entry / "size", 32)
        rotational = _read_first_line(entry / "queue/rotational", 4)
        devices.append({
            "name": entry.name,
            "size_bytes": int(sectors) * 512 if sectors and sectors.isdigit() else None,
            "rotational": (rotational == "1") if rotational in {"0", "1"} else None,
            "removable": _read_first_line(entry / "removable", 4) == "1",
            "model": _read_first_line(entry / "device/model", 128),
            "kind": "nvme" if entry.name.startswith("nvme") else "virtual" if entry.name.startswith(("vd", "xvd")) else "disk",
        })
    return devices


def collect_storage() -> dict[str, Any]:
    filesystems: list[dict[str, Any]] = []
    seen_devices: set[str] = set()
    candidates = sorted(_host_mounts(), key=lambda item: (len(item["mountpoint"]), item["mountpoint"]))
    for mount in candidates:
        mountpoint, device, fstype = mount["mountpoint"], mount["device"], mount["filesystem"]
        if fstype in _PSEUDO_FS or mountpoint.startswith(_SKIP_MOUNT_PREFIXES):
            continue
        is_block = device.startswith("/dev/") and not re.match(r"^/dev/(loop|zram|ram)\d*", device)
        if not (is_block or fstype in _NETWORK_FS or fstype == "zfs"):
            continue
        if device in seen_devices:
            continue  # bind mounts / btrfs subvolumes of a device we already reported
        try:
            usage = shutil.disk_usage(_proc_mount_path(mountpoint))
        except OSError:
            continue
        if usage.total <= 0:
            continue
        seen_devices.add(device)
        capacity = usage.used + usage.free  # same basis as `df`: reserved blocks are not counted
        filesystems.append({
            "device": device,
            "mountpoint": mountpoint,
            "filesystem": fstype,
            "options": mount["options"],
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent": round(usage.used / capacity * 100, 2) if capacity else None,
            "status": "available",
        })

    mdstat = _read_text(HOST_PROC / "mdstat", 256_000)
    raid_arrays = _parse_mdstat(mdstat)
    return _status_data({
        "filesystems": filesystems,
        "disk_io": _disk_io(),
        "block_devices": _block_devices(),
        "raid": {"detected": bool(raid_arrays), "arrays": raid_arrays, "mdstat_raw": mdstat},
    }, "available" if filesystems else "partial")


def _host_net_file(name: str) -> str:
    """Contents of /proc/net/<name> as seen by the HOST.

    /host/proc/net is a symlink to `self/net`, i.e. the *collector container's own* network
    namespace (it only has eth0).  PID 1 lives in the host namespace, so /host/proc/1/net/<name>
    is the real host view (wlan0, enp3s0, ...).  Falls back to the container view if unreadable.
    """
    for path in (HOST_PROC / "1" / "net" / name, HOST_PROC / "net" / name, Path("/proc/net") / name):
        text = _read_text(path, 4_000_000)
        if text.strip():
            return text
    return ""


def _parse_proc_net_dev() -> dict[str, dict[str, int]]:
    interfaces = {}
    content = _host_net_file("dev")
    for line in content.splitlines():
        if ":" not in line:
            continue
        iface, data = line.split(":", 1)
        iface = iface.strip()
        parts = data.split()
        if len(parts) >= 16:
            try:
                interfaces[iface] = {
                    "bytes_recv": int(parts[0]),
                    "packets_recv": int(parts[1]),
                    "errors_in": int(parts[2]),
                    "drops_in": int(parts[3]),
                    "bytes_sent": int(parts[8]),
                    "packets_sent": int(parts[9]),
                    "errors_out": int(parts[10]),
                    "drops_out": int(parts[11]),
                }
            except ValueError:
                continue
    return interfaces


def _interface_details() -> dict[str, dict[str, Any]]:
    """Link state, speed, MTU, MAC, wired/wireless/virtual kind and IP addresses per interface."""
    details: dict[str, dict[str, Any]] = {}
    base = HOST_SYS / "class/net"
    try:
        names = sorted(item.name for item in base.iterdir())
    except OSError:
        return details
    try:
        addresses = psutil.net_if_addrs()
    except (OSError, RuntimeError):
        addresses = {}
    for name in names:
        link = base / name
        speed = _read_first_line(link / "speed", 16)
        mtu = _read_first_line(link / "mtu", 16)
        real = os.path.realpath(link)
        if name == "lo":
            kind = "loopback"
        elif (link / "wireless").exists() or (link / "phy80211").exists():
            kind = "wireless"
        elif "/devices/virtual/" in real:
            kind = "virtual"
        else:
            kind = "ethernet"
        details[name] = {
            "state": _read_first_line(link / "operstate", 32),
            "speed_mbps": int(speed) if speed and speed.lstrip("-").isdigit() and int(speed) > 0 else None,
            "mtu": int(mtu) if mtu and mtu.isdigit() else None,
            "mac": _read_first_line(link / "address", 32),
            "kind": kind,
            "addresses": [{"family": "ipv6" if item.family == socket.AF_INET6 else "ipv4", "address": item.address.split("%")[0], "netmask": item.netmask}
                          for item in addresses.get(name, []) if item.family in (socket.AF_INET, socket.AF_INET6)],
        }
    return details


def collect_network() -> dict[str, Any]:
    interfaces = _parse_proc_net_dev()
    if not interfaces:
        try:
            for name, counters in psutil.net_io_counters(pernic=True, nowrap=True).items():
                interfaces[name] = {
                    "bytes_sent": counters.bytes_sent,
                    "bytes_recv": counters.bytes_recv,
                    "packets_sent": counters.packets_sent,
                    "packets_recv": counters.packets_recv,
                    "errors_in": counters.errin,
                    "errors_out": counters.errout,
                    "drops_in": counters.dropin,
                    "drops_out": counters.dropout,
                }
        except (OSError, RuntimeError):
            pass
    rates = _RATE_SAMPLER.network_rates()
    details = _interface_details()
    for name, counters in interfaces.items():
        counters.update(rates.get(name, {}))  # rx/tx_bytes_per_sec, rx/tx_packets_per_sec when measured
        counters.update(details.get(name, {}))
    protocols = {}
    pending_headers: dict[str, list[str]] = {}
    for line in _host_net_file("snmp").splitlines():
        fields = line.split()
        if len(fields) > 1 and fields[0].endswith(":"):
            protocol = fields[0][:-1]
            columns = fields[1:]
            if protocol not in pending_headers:
                pending_headers[protocol] = columns
                continue
            names = pending_headers.pop(protocol)
            protocols[protocol] = {
                name: int(value) if value.lstrip("-").isdigit() else value
                for name, value in zip(names, columns)
            }
    return _status_data(
        {"interfaces": interfaces, "protocol_counters": protocols, "firewall": _firewall_state()},
        "available" if interfaces else "partial",
    )


def _firewall_state_uncached() -> dict[str, Any]:
    # Report rules only when the host's nft binary and network namespace are usable.
    nft = shutil.which("nft")
    nsenter = shutil.which("nsenter")
    try:
        host_net_namespace_available = (HOST_PROC / "1/ns/net").exists()
    except OSError:
        # Container proc mounts can hide namespace links or deny stat access.
        # Capability discovery should report that limitation instead of failing.
        host_net_namespace_available = False
    if not nft or not nsenter or not host_net_namespace_available:
        return {"status": "unavailable", "reason": "nftables or host network namespace is unavailable or inaccessible"}
    try:
        result = subprocess.run(
            [nsenter, f"--net={HOST_PROC / '1/ns/net'}", nft, "-j", "list", "ruleset"],
            capture_output=True, text=True, timeout=3, check=False,
        )
        if result.returncode:
            return {"status": "permission_denied", "reason": result.stderr.strip()[:300]}
        return {"status": "available", "ruleset": json.loads(result.stdout)}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "reason": str(exc)[:300]}



_FIREWALL_CACHE: dict[str, Any] = {"at": 0.0, "value": None}
_FIREWALL_TTL_SECONDS = 300.0


def _firewall_state() -> dict[str, Any]:
    # `nft list ruleset` is comparatively expensive; the ruleset rarely changes, so reuse it for a few minutes.
    now = time.monotonic()
    if _FIREWALL_CACHE["value"] is not None and now - _FIREWALL_CACHE["at"] < _FIREWALL_TTL_SECONDS:
        return _FIREWALL_CACHE["value"]
    value = _firewall_state_uncached()
    _FIREWALL_CACHE.update(at=now, value=value)
    return value


def collect_processes() -> dict[str, Any]:
    rates = _RATE_SAMPLER.process_rates()  # % of ONE core, from two real reads; empty until measured
    cores = len(_CPU_SAMPLER.current()["cores"] or []) if _CPU_SAMPLER.current() else 0
    cores = cores or psutil.cpu_count(logical=True) or 1
    rows: list[dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=["pid", "name", "status", "memory_info", "num_threads", "username", "create_time", "cpu_times"]):
        try:
            item = proc.info
            pid = item.get("pid")
            memory = item.get("memory_info")
            cpu_times = item.get("cpu_times")
            created = item.get("create_time")
            total_cpu_time = (cpu_times.user + cpu_times.system) if cpu_times else None
            measured = rates.get(pid)
            core_pct = None
            if measured is not None and created is not None and abs(float(created) - measured[0]) <= PID_REUSE_TOLERANCE_SECONDS:
                core_pct = measured[1]
            rows.append({
                "pid": pid, "name": item.get("name"), "status": item.get("status"),
                "rss_bytes": memory.rss if memory else None, "threads": item.get("num_threads"),
                "username": item.get("username"), "started_at": created,
                "cpu_time_seconds": total_cpu_time,
                # cpu_pct: share of the WHOLE machine (0-100, comparable with the system CPU figure).
                # cpu_core_pct: share of one core, like `top` (can exceed 100 for multi-threaded processes).
                # Both are None - not 0 - for a process that has not been measured twice yet.
                "cpu_pct": round(min(100.0, core_pct / cores), 2) if core_pct is not None else None,
                "cpu_core_pct": round(core_pct, 2) if core_pct is not None else None,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    by_rss = sorted(rows, key=lambda row: row.get("rss_bytes") or 0, reverse=True)[:100]
    by_cpu = sorted((row for row in rows if row["cpu_core_pct"]), key=lambda row: row["cpu_core_pct"], reverse=True)[:40]
    selected = {row["pid"]: row for row in (*by_rss, *by_cpu)}  # a busy small process must not be dropped
    top = sorted(selected.values(), key=lambda row: row.get("rss_bytes") or 0, reverse=True)

    oom = {}
    for line in _read_text(HOST_PROC / "vmstat", 256_000).splitlines():
        key, _, value = line.partition(" ")
        if key in {"oom_kill", "oom_reaper"}:
            try:
                oom[key] = int(value.strip())
            except ValueError:
                pass
    return _status_data(
        {"process_count": len(rows), "top_by_rss": top, "oom_counters": oom, "cpu_rates_measured": bool(rates)},
        "available" if rows else "partial",
    )


_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
               "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
_MAX_SOCKETS = 5000


def _decode_socket_address(value: str, ipv6: bool) -> tuple[str, int] | None:
    try:
        host, port = value.split(":")
        raw = bytes.fromhex(host)
        if ipv6:
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            return socket.inet_ntop(socket.AF_INET6, raw), int(port, 16)
        return socket.inet_ntop(socket.AF_INET, raw[::-1]), int(port, 16)
    except (ValueError, OSError):
        return None


def _socket_inode_owners(wanted: set[str]) -> dict[str, int]:
    """Map socket inode -> pid with ONE pass over /proc/<pid>/fd."""
    owners: dict[str, int] = {}
    if not wanted:
        return owners
    proc_dirs = [HOST_PROC]
    if HOST_PROC != Path("/proc") and Path("/proc").exists():
        proc_dirs.append(Path("/proc"))
    for proc_dir in proc_dirs:
        try:
            entries = [entry for entry in os.scandir(proc_dir) if entry.name.isdigit()]
        except OSError:
            continue
        for entry in entries:
            if len(owners) >= len(wanted):
                return owners
            try:
                for fd in os.scandir(f"{entry.path}/fd"):
                    try:
                        target = os.readlink(fd.path)
                    except OSError:
                        continue
                    if target.startswith("socket:[") and target[8:-1] in wanted:
                        owners.setdefault(target[8:-1], int(entry.name))
            except (OSError, PermissionError):
                continue
    return owners


def collect_connections() -> dict[str, Any]:
    # Read the HOST's socket tables (not this container's) and resolve owners in a single pass.
    parsed: list[dict[str, Any]] = []
    for table, kind, ipv6 in (("tcp", "tcp", False), ("tcp6", "tcp", True), ("udp", "udp", False), ("udp6", "udp", True)):
        for line in _host_net_file(table).splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                continue
            local = _decode_socket_address(fields[1], ipv6)
            remote = _decode_socket_address(fields[2], ipv6)
            if local is None:
                continue
            connected = remote is not None and remote[1] != 0
            parsed.append({
                "family": "ipv6" if ipv6 else "ipv4", "type": kind, "local": local,
                "remote": remote if connected else None,
                "state": _TCP_STATES.get(fields[3].upper(), "UNKNOWN") if kind == "tcp" else "NONE",
                "inode": fields[9],
            })
            if len(parsed) >= _MAX_SOCKETS:
                break
    if not parsed:
        return _status_data({"count": 0, "truncated": False, "sockets": []}, "partial")

    owners = _socket_inode_owners({row["inode"] for row in parsed if row["inode"] != "0"})
    names: dict[int, str | None] = {}

    def process_name(pid: int | None) -> str | None:
        if pid is None:
            return None
        if pid not in names:
            text = _read_text(HOST_PROC / str(pid) / "comm", 256).strip()
            if not text:
                cmd = _read_text(HOST_PROC / str(pid) / "cmdline", 512).replace("\x00", " ").strip()
                if cmd:
                    text = Path(cmd.split()[0]).name
            names[pid] = text or None
        return names[pid]

    rows = []
    for row in parsed:
        pid = owners.get(row["inode"])
        rows.append({
            "pid": pid, "process": process_name(pid), "family": row["family"], "type": row["type"],
            "local_address": row["local"][0], "local_port": row["local"][1],
            "remote_address": row["remote"][0] if row["remote"] else None,
            "remote_port": row["remote"][1] if row["remote"] else None,
            "state": row["state"],
        })
    return _status_data({"count": len(rows), "truncated": len(rows) >= _MAX_SOCKETS, "sockets": rows})


def _service_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [row for row in rows if row["unit"].endswith(".service")]


def _systemd_via_busctl(bus: Path) -> list[dict[str, str]] | None:
    """Ask the HOST's systemd over D-Bus (works from a container, unlike systemctl)."""
    busctl = shutil.which("busctl")
    if not busctl:
        return None
    try:
        result = subprocess.run(
            [busctl, f"--address=unix:path={bus}", "call", "org.freedesktop.systemd1",
             "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "ListUnits", "--json=short"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode:
            return None
        # ListUnits returns a(ssssssouso): name, description, load, active, sub, followed, path, job...
        units = json.loads(result.stdout)["data"][0]
        return _service_rows([
            {"unit": str(u[0]), "description": str(u[1]), "load": str(u[2]), "active": str(u[3]), "sub": str(u[4])}
            for u in units if isinstance(u, list) and len(u) >= 5
        ])
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, IndexError, TypeError):
        return None


def _systemd_via_systemctl(bus: Path | None) -> tuple[list[dict[str, str]], str]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return [], "unavailable"
    env = dict(os.environ)
    if bus is not None:
        env["DBUS_SYSTEM_BUS_ADDRESS"] = f"unix:path={bus}"
    try:
        result = subprocess.run(
            [systemctl, "--no-pager", "--all", "--type=service", "--output=json", "list-units"],
            capture_output=True, text=True, timeout=5, check=False, env=env,
        )
        if result.returncode:
            return [], "permission_denied"
        parsed = json.loads(result.stdout)
        if isinstance(parsed, dict):
            parsed = parsed.get("units", [])
        if not isinstance(parsed, list):
            return [], "unavailable"
        return _service_rows([
            {"unit": str(row.get("unit", "")), "load": str(row.get("load", "")), "active": str(row.get("active", "")),
             "sub": str(row.get("sub", "")), "description": str(row.get("description", ""))}
            for row in parsed if isinstance(row, dict)
        ]), "available"
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return [], "unavailable"


def _systemd_services() -> tuple[list[dict[str, str]], str]:
    bus = next((path for path in (Path("/host/run/dbus/system_bus_socket"), Path("/run/dbus/system_bus_socket"))
                if path.exists()), None)
    if bus is not None:
        # systemctl refuses to run inside a container ("Running in chroot, ignoring command"),
        # so talk to the host's systemd directly over its D-Bus socket first.
        services = _systemd_via_busctl(bus)
        if services is not None:
            return services, "available"
    # Bare-metal install (no container): plain systemctl still works.
    return _systemd_via_systemctl(bus)


def collect_services() -> dict[str, Any]:
    services, status = _systemd_services()
    return _status_data({"manager": "systemd", "services": services}, status)


_MAX_API_BYTES = 50_000_000


def _unix_request(socket_path: Path, request_path: str, timeout: float = 5.0, method: str = "GET") -> tuple[int, bytes]:
    import http.client

    class UnixConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect(str(socket_path))

    connection = UnixConnection("localhost", timeout=timeout)
    try:
        connection.request(method, request_path, headers={"Host": "localhost"})
        response = connection.getresponse()
        return response.status, response.read(_MAX_API_BYTES)
    finally:
        connection.close()


def _docker_request(path: str, timeout: float = 5.0) -> Any:
    if not DOCKER_SOCKET.exists() or not DOCKER_SOCKET.is_socket():
        raise FileNotFoundError("Docker/Podman socket not mounted")
    status, body = _unix_request(DOCKER_SOCKET, path, timeout)
    if status != 200:
        raise OSError(f"Docker API returned HTTP {status}")
    return json.loads(body)


def _container_stats(container_id: str) -> dict[str, Any]:
    try:
        stats = _docker_request(f"/containers/{container_id}/stats?stream=false", timeout=15.0)
        memory = stats.get("memory_stats") or {}
        cpu = stats.get("cpu_stats") or {}
        previous = stats.get("precpu_stats") or {}
        cpu_delta = (cpu.get("cpu_usage") or {}).get("total_usage", 0) - (previous.get("cpu_usage") or {}).get("total_usage", 0)
        system_delta = cpu.get("system_cpu_usage", 0) - previous.get("system_cpu_usage", 0)
        online = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
        cpu_pct = (cpu_delta / system_delta * online * 100) if system_delta > 0 and cpu_delta >= 0 else None

        usage = memory.get("usage")
        mem_stats = memory.get("stats") or {}
        # `docker stats` shows the working set: usage minus reclaimable page cache
        cache = mem_stats.get("inactive_file", mem_stats.get("total_inactive_file", mem_stats.get("cache")))
        working = usage - cache if isinstance(usage, (int, float)) and isinstance(cache, (int, float)) and usage >= cache else usage

        networks = stats.get("networks") or {}
        block = (stats.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
        block_read = sum(item.get("value", 0) for item in block if str(item.get("op", "")).lower() == "read")
        block_write = sum(item.get("value", 0) for item in block if str(item.get("op", "")).lower() == "write")
        return {
            "memory_usage_bytes": working,
            "memory_raw_usage_bytes": usage,
            "memory_limit_bytes": memory.get("limit"),
            "cpu_percent": cpu_pct,
            "net_rx_bytes": sum(item.get("rx_bytes", 0) for item in networks.values()) if networks else None,
            "net_tx_bytes": sum(item.get("tx_bytes", 0) for item in networks.values()) if networks else None,
            "block_read_bytes": block_read if block else None,
            "block_write_bytes": block_write if block else None,
            "pids": (stats.get("pids_stats") or {}).get("current"),
        }
    except (OSError, json.JSONDecodeError, TypeError, ValueError, AttributeError):
        return {}


def collect_containers() -> dict[str, Any]:
    sources: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    docker_status = "not_configured"
    docker_reason = "Docker/Podman socket not present"
    try:
        containers = _docker_request("/containers/json?all=1", timeout=10.0)
        docker_status, docker_reason = "available", None
    except FileNotFoundError:
        containers = []
    except (OSError, json.JSONDecodeError) as exc:
        containers = []
        docker_status, docker_reason = "unavailable", str(exc)[:300]
    containers = containers[:500]
    active = [item for item in containers if item.get("State") == "running"][:100]
    with ThreadPoolExecutor(max_workers=16) as pool:
        stats_by_id = dict(zip(
            (item.get("Id", "") for item in active),
            pool.map(_container_stats, (item.get("Id", "") for item in active)),
        ))
    for container in containers:
        cid = container.get("Id", "")
        metrics = stats_by_id.get(cid, {})
        labels = container.get("Labels") or {}
        safe_labels = {key: "[REDACTED]" if SENSITIVE_KEY.search(key) else value for key, value in labels.items()}
        ports = [{"private": port.get("PrivatePort"), "public": port.get("PublicPort"), "type": port.get("Type"), "ip": port.get("IP")} for port in (container.get("Ports") or []) if isinstance(port, dict)]
        rows.append({"runtime": "docker", "id": cid[:12], "name": (container.get("Names") or [""])[0].lstrip("/"), "image": container.get("Image"), "state": container.get("State"), "status": container.get("Status"), "created": container.get("Created"), "command": _redact_text(str(container.get("Command") or ""))[:300], "ports": ports, "labels": safe_labels, "metrics": metrics})
    sources["docker"] = {
        "status": docker_status,
        "reason": docker_reason,
        "count": len(containers),
        "stats_count": len(active),
        "stats_truncated": len([item for item in containers if item.get("State") == "running"]) > len(active),
    }

    lxd_path = LXD_SOCKET
    if not lxd_path.exists():
        sources["lxd"] = {"status": "not_configured", "count": 0, "reason": "LXD socket not present"}
    else:
        try:
            lxd = _unix_http_get(lxd_path, "/1.0/instances?recursion=1")
            instances = lxd.get("metadata", []) if isinstance(lxd, dict) else []
            for item in instances:
                rows.append({"runtime": "lxd", "name": item.get("name"), "type": item.get("type"), "status": item.get("status"), "architecture": item.get("architecture"), "profiles": item.get("profiles", []), "config": {key: value for key, value in (item.get("config") or {}).items() if key.startswith("limits.")}})
            sources["lxd"] = {"status": "available", "count": len(instances)}
        except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
            sources["lxd"] = {"status": "unavailable", "count": 0, "reason": str(exc)[:300]}

    lxc_rows = _collect_legacy_lxc()
    if lxc_rows is not None:
        rows.extend(lxc_rows)
        sources["lxc"] = {"status": "available", "count": len(lxc_rows)}

    kube = _collect_kubernetes()
    if kube["status"] == "available":
        rows.extend(kube["pods"])
    sources["kubernetes"] = {"status": kube["status"], "reason": kube.get("reason"), "count": len(kube.get("pods", []))}
    source_statuses = [item.get("status") for item in sources.values()]
    # "available" = at least one runtime answered (even with 0 containers); a runtime that is present
    # but failing is "unavailable"; nothing present at all is "not_configured".
    if "available" in source_statuses:
        status = "available"
    elif "unavailable" in source_statuses:
        status = "unavailable"
    else:
        status = "not_configured"
    return _status_data({"containers": rows, "sources": sources}, status)


def _running_lxc_names() -> set[str]:
    names: set[str] = set()
    try:
        entries = [entry for entry in os.scandir(HOST_PROC) if entry.name.isdigit()]
    except OSError:
        return names
    for entry in entries:
        cmdline = _read_text(Path(entry.path) / "cmdline", 1024).replace("\x00", " ")
        match = re.search(r"\[lxc monitor\]\s+\S+\s+(\S+)", cmdline)
        if match:
            names.add(match.group(1))
    return names


def _collect_legacy_lxc() -> list[dict[str, Any]] | None:
    """Classic LXC / Proxmox-style containers defined under /var/lib/lxc (None when LXC is not used)."""
    base = HOST_ROOT / "var/lib/lxc"
    try:
        names = sorted(item.name for item in base.iterdir() if (item / "config").is_file())
    except OSError:
        return None
    running = _running_lxc_names()
    return [{"runtime": "lxc", "id": name, "name": name, "image": None, "state": "running" if name in running else "stopped", "status": "running" if name in running else "stopped"} for name in names]


def _collect_kubernetes() -> dict[str, Any]:
    if not KUBERNETES_API_URL or not KUBERNETES_TOKEN:
        return {"status": "not_configured", "pods": [], "reason": "Kubernetes API URL/token not configured"}
    headers = {"Authorization": f"Bearer {KUBERNETES_TOKEN}"}
    verify: str | bool = KUBERNETES_CA_CERT or True
    try:
        response = httpx.get(f"{KUBERNETES_API_URL}/api/v1/pods", headers=headers, verify=verify, timeout=5.0)
        response.raise_for_status()
        items = response.json().get("items", [])
        pod_metrics: dict[tuple[str, str], Any] = {}
        try:
            metrics_response = httpx.get(f"{KUBERNETES_API_URL}/apis/metrics.k8s.io/v1beta1/pods", headers=headers, verify=verify, timeout=5.0)
            metrics_response.raise_for_status()
            for metric in metrics_response.json().get("items", []):
                metadata = metric.get("metadata", {})
                pod_metrics[(metadata.get("namespace", "default"), metadata.get("name", ""))] = metric.get("containers", [])
        except (httpx.HTTPError, ValueError):
            pass
        pods = []
        for item in items[:1000]:
            metadata = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})
            namespace = metadata.get("namespace", "default")
            name = metadata.get("name", "")
            pods.append({"runtime": "kubernetes", "namespace": namespace, "name": name, "node": spec.get("nodeName"), "phase": status.get("phase"), "pod_ip": status.get("podIP"), "containers": status.get("containerStatuses", []), "resource_metrics": pod_metrics.get((namespace, name), [])})
        return {"status": "available", "pods": pods}
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "unavailable", "pods": [], "reason": str(exc)[:300]}


def _unix_http_get(path: Path, request_path: str) -> Any:
    if not path.exists() or not path.is_socket():
        raise FileNotFoundError(str(path))
    status, content = _unix_request(path, request_path, 5.0)
    if status != 200:
        raise OSError(f"runtime API returned HTTP {status}")
    payload = json.loads(content)
    if isinstance(payload, dict) and payload.get("type") == "async":
        operation = payload.get("operation", "").rstrip("/")
        if operation:
            return _unix_http_get(path, operation + "/wait")
    return payload


def _parse_kib_to_bytes(value: str | None) -> int | None:
    """'8192000 KiB' -> bytes (virsh dominfo style)."""
    if not value:
        return None
    parts = value.split()
    try:
        number = int(parts[0])
    except (ValueError, IndexError):
        return None
    unit = parts[1].lower() if len(parts) > 1 else "kib"
    if "gib" in unit or unit == "gb":
        return number * 1024 ** 3
    if "mib" in unit or unit == "mb":
        return number * 1024 ** 2
    if "kib" in unit or unit == "kb":
        return number * 1024
    return number


def _qemu_size_to_bytes(value: str) -> int | None:
    match = re.match(r"^(?:size=)?(\d+)([kKmMgGtT]?)", value.strip())
    if not match:
        return None
    factor = {"": 1024 ** 2, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}[match.group(2).lower()]
    return int(match.group(1)) * factor  # a bare number is MiB for QEMU's -m


def _qemu_processes() -> list[dict[str, Any]]:
    """Running QEMU/KVM guests, read from the HOST process table.

    Needs no socket or credentials, so it also finds Proxmox guests, hand-started QEMU and libvirt
    guests when the management API is not reachable.
    """
    rates = _RATE_SAMPLER.process_rates()
    cores = (len(_CPU_SAMPLER.current()["cores"]) if _CPU_SAMPLER.current() else 0) or psutil.cpu_count(logical=True) or 1
    guests: list[dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline", "memory_info", "create_time"]):
        info = proc.info
        name = str(info.get("name") or "")
        if not (name.startswith("qemu-system") or name in {"kvm", "qemu-kvm", "qemu"}):
            continue
        args = info.get("cmdline") or []
        guest: dict[str, Any] = {"pid": info["pid"]}
        for index, arg in enumerate(args[:-1]):
            value = args[index + 1]
            if arg == "-name":
                first = value.split(",")[0]
                guest["name"] = first[6:] if first.startswith("guest=") else first
            elif arg == "-id" and value.isdigit():
                guest["vmid"] = int(value)
            elif arg == "-uuid":
                guest["uuid"] = value
            elif arg == "-smp":
                count = re.match(r"^(?:cpus=)?(\d+)", value)
                if count:
                    guest["cpu_count"] = int(count.group(1))
            elif arg == "-m":
                guest["max_memory"] = _qemu_size_to_bytes(value.split(",")[0])
        memory = info.get("memory_info")
        measured = rates.get(info["pid"])
        core_pct = measured[1] if measured and info.get("create_time") is not None and abs(float(info["create_time"]) - measured[0]) <= PID_REUSE_TOLERANCE_SECONDS else None
        guest.update({
            "rss_bytes": memory.rss if memory else None,
            "cpu_core_pct": round(core_pct, 2) if core_pct is not None else None,
            "cpu_pct": round(min(100.0, core_pct / cores), 2) if core_pct is not None else None,
        })
        guest.setdefault("name", f"qemu-{info['pid']}")
        guests.append(guest)
    return guests


def _libvirt_domain(virsh: str, uri: str, name: str, qemu_by_name: dict[str, dict[str, Any]]) -> dict[str, Any]:
    info = subprocess.run([virsh, "--connect", uri, "dominfo", name], capture_output=True, text=True, timeout=5, check=False)
    parsed: dict[str, str] = {}
    for line in info.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            parsed[key.strip().lower().replace(" ", "_")] = value.strip()

    raw_state = parsed.get("state", "unknown")
    max_mem_bytes = _parse_kib_to_bytes(parsed.get("max_memory"))
    used_mem_bytes = None
    if "running" in raw_state.lower():
        stat_res = subprocess.run([virsh, "--connect", uri, "dommemstat", name], capture_output=True, text=True, timeout=3, check=False)
        if stat_res.returncode == 0:
            stats: dict[str, int] = {}
            for sline in stat_res.stdout.splitlines():
                sparts = sline.split()
                if len(sparts) >= 2:
                    try:
                        stats[sparts[0].lower()] = int(sparts[1])
                    except ValueError:
                        pass
            if "available" in stats and "usable" in stats:
                used_mem_bytes = (stats["available"] - stats["usable"]) * 1024
            elif "actual" in stats and "unused" in stats:
                used_mem_bytes = (stats["actual"] - stats["unused"]) * 1024
            elif "rss" in stats:
                used_mem_bytes = stats["rss"] * 1024
            elif "actual" in stats:
                used_mem_bytes = stats["actual"] * 1024
        if used_mem_bytes is None:
            used_mem_bytes = _parse_kib_to_bytes(parsed.get("used_memory"))

    process = qemu_by_name.get(name) or qemu_by_name.get(parsed.get("uuid", ""))
    return {
        "runtime": "libvirt",
        "name": name,
        "state": raw_state,
        "cpu_count": parsed.get("cpu(s)"),
        "max_memory": max_mem_bytes,
        "used_memory": used_mem_bytes,
        "uuid": parsed.get("uuid"),
        "autostart": parsed.get("autostart"),
        "persistent": parsed.get("persistent"),
        # live host-side usage of the guest (from its QEMU process); None when not measured
        "cpu_pct": process.get("cpu_pct") if process else None,
        "rss_bytes": process.get("rss_bytes") if process else None,
        "pid": process.get("pid") if process else None,
    }


def _collect_libvirt(qemu: list[dict[str, Any]]) -> dict[str, Any]:
    virsh = shutil.which("virsh")
    if not LIBVIRT_SOCKET.exists():
        return {"status": "not_configured", "vms": [], "reason": "libvirt socket not present"}
    if not virsh:
        return {"status": "unavailable", "vms": [], "reason": "virsh client is not installed in the collector image"}
    uri = f"qemu+unix:///system?socket={LIBVIRT_SOCKET}"
    try:
        result = subprocess.run([virsh, "--connect", uri, "list", "--all", "--name"], capture_output=True, text=True, timeout=8, check=False)
        if result.returncode:
            return {"status": "unavailable", "vms": [], "reason": result.stderr.strip()[:300]}
        names = [name.strip() for name in result.stdout.splitlines() if name.strip()][:500]
        by_name = {guest["name"]: guest for guest in qemu}
        by_name.update({guest["uuid"]: guest for guest in qemu if guest.get("uuid")})
        with ThreadPoolExecutor(max_workers=8) as pool:
            vms = list(pool.map(lambda item: _libvirt_domain(virsh, uri, item, by_name), names))
        return {"status": "available", "vms": vms}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unavailable", "vms": [], "reason": str(exc)[:300]}


def collect_vms() -> dict[str, Any]:
    qemu = _qemu_processes()
    libvirt = _collect_libvirt(qemu)
    proxmox = _collect_proxmox()

    vms: list[dict[str, Any]] = list(libvirt["vms"]) + list(proxmox.get("vms", []))
    known_names = {str(vm.get("name")) for vm in vms}
    known_vmids = {vm.get("vmid") for vm in proxmox.get("vms", []) if vm.get("vmid") is not None}
    # Guests visible only as QEMU processes (Proxmox without API token, plain QEMU, libvirt without a socket)
    process_only = [guest for guest in qemu if guest["name"] not in known_names and guest.get("vmid") not in known_vmids]
    for guest in process_only:
        vms.append({
            "runtime": "proxmox-qemu" if guest.get("vmid") is not None else "qemu-process",
            "name": guest["name"], "vmid": guest.get("vmid"), "state": "running", "cpu_count": guest.get("cpu_count"),
            "max_memory": guest.get("max_memory"), "used_memory": guest.get("rss_bytes"),
            "cpu_pct": guest.get("cpu_pct"), "rss_bytes": guest.get("rss_bytes"), "pid": guest.get("pid"), "uuid": guest.get("uuid"),
        })

    sources = {
        "libvirt": {"status": libvirt["status"], "count": len(libvirt["vms"]), "reason": libvirt.get("reason")},
        "proxmox": {"status": proxmox["status"], "count": len(proxmox.get("vms", [])), "reason": proxmox.get("reason")},
        "qemu_processes": {"status": "available" if qemu else "not_configured", "count": len(process_only),
                           "reason": None if qemu else "No QEMU/KVM guest process is running on this host"},
    }
    statuses = [item["status"] for item in sources.values()]
    if "available" in statuses:
        status = "available"
    elif "unavailable" in statuses:
        status = "unavailable"
    else:
        status = "not_configured"
    data: dict[str, Any] = {"sources": sources, "vms": vms}
    if status == "not_configured":
        data["reason"] = "No hypervisor (libvirt / Proxmox / QEMU) is running on this host"
    return _status_data(data, status)


def _collect_proxmox() -> dict[str, Any]:
    if not PROXMOX_API_URL or not PROXMOX_API_TOKEN:
        return {"status": "not_configured", "vms": [], "reason": "Proxmox API URL/token not configured"}
    headers = {"Authorization": f"PVEAPIToken={PROXMOX_API_TOKEN}"}
    verify: str | bool = False if PROXMOX_INSECURE_TLS else (PROXMOX_CA_CERT or True)
    try:
        nodes = httpx.get(f"{PROXMOX_API_URL}/api2/json/nodes", headers=headers, verify=verify, timeout=5.0)
        nodes.raise_for_status()
        vms = []
        for node in nodes.json().get("data", []):
            node_name = node.get("node")
            for runtime in ("qemu", "lxc"):
                response = httpx.get(f"{PROXMOX_API_URL}/api2/json/nodes/{node_name}/{runtime}", headers=headers, verify=verify, timeout=5.0)
                response.raise_for_status()
                for item in response.json().get("data", []):
                    cpu = item.get("cpu")
                    vms.append({
                        "runtime": "proxmox-" + runtime, "node": node_name, "vmid": item.get("vmid"), "name": item.get("name"),
                        "status": item.get("status"), "state": item.get("status"),
                        "cpu": cpu, "cpu_pct": round(cpu * 100, 2) if isinstance(cpu, (int, float)) else None,  # cpu is a 0-1 share of the VM's vCPUs
                        "cpu_count": item.get("cpus"),
                        "memory_bytes": item.get("mem"), "max_memory_bytes": item.get("maxmem"),
                        "used_memory": item.get("mem"), "max_memory": item.get("maxmem"),
                        "uptime_seconds": item.get("uptime"),
                    })
        return {"status": "available", "vms": vms}
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "unavailable", "vms": [], "reason": str(exc)[:300]}


COLLECTORS = {
    "system": collect_system,
    "storage": collect_storage,
    "network": collect_network,
    "services": collect_services,
    "processes": collect_processes,
    "connections": collect_connections,
    "containers": collect_containers,
    "vms": collect_vms,
}


def discover_capabilities() -> dict[str, Any]:
    capabilities = {name: {"status": "available", "source": "linux host collector"} for name in CATEGORIES}
    journal_available = bool(shutil.which("journalctl") and any(path.is_dir() for path in (HOST_LOG / "journal", Path("/host/run/log/journal"))))
    app_logs_available = any(glob.glob(pattern, recursive=True) for pattern in APP_LOG_GLOBS)
    capabilities["logs"] = {
        "status": "available" if journal_available or app_logs_available else "unavailable",
        "sources": ["systemd journal", "configured application log files"],
        "reason": None if journal_available or app_logs_available else "journal and configured application log files are unavailable",
    }
    def is_socket(path: Path) -> bool:
        try:
            return path.exists() and path.is_socket()
        except OSError:
            return False

    docker_ok, lxd_ok = is_socket(DOCKER_SOCKET), is_socket(LXD_SOCKET)
    kube_ok = bool(KUBERNETES_API_URL and KUBERNETES_TOKEN)
    legacy_lxc = (HOST_ROOT / "var/lib/lxc").is_dir()
    capabilities["containers"] = {
        "status": "available" if (docker_ok or lxd_ok or kube_ok or legacy_lxc) else "not_configured",
        "sources": {"docker": docker_ok, "lxd": lxd_ok, "kubernetes": kube_ok, "lxc": legacy_lxc},
        "reason": None if (docker_ok or lxd_ok or kube_ok or legacy_lxc) else "No Docker/Podman/LXD socket, LXC directory or Kubernetes credentials found on this host",
    }
    containerd_socket = Path("/host/run/containerd/containerd.sock")
    capabilities["containerd"] = {
        "status": "not_configured" if containerd_socket.exists() else "unavailable",
        "reason": "containerd CRI collection is not configured" if containerd_socket.exists() else "containerd socket not present",
    }
    capabilities["lxc"] = {
        "status": "available" if legacy_lxc else "not_configured",
        "reason": "legacy LXC definitions found" if legacy_lxc else "legacy LXC is not present",
    }
    libvirt_ok = bool(shutil.which("virsh") and is_socket(LIBVIRT_SOCKET))
    proxmox_ok = bool(PROXMOX_API_URL and PROXMOX_API_TOKEN)
    qemu_ok = bool(_qemu_processes())
    capabilities["vms"] = {
        "status": "available" if (libvirt_ok or proxmox_ok or qemu_ok) else "not_configured",
        "sources": {"libvirt": libvirt_ok, "proxmox": proxmox_ok, "qemu_processes": qemu_ok},
        "reason": None if (libvirt_ok or proxmox_ok or qemu_ok) else "No hypervisor (libvirt / Proxmox / QEMU) found on this host",
    }
    capabilities["firewall"] = _firewall_state()
    cpu_now = _CPU_SAMPLER.current()
    capabilities["cpu_sampling"] = {
        "status": "available" if cpu_now else "unavailable",
        "interval_seconds": CPU_SAMPLE_INTERVAL,
        "buffer_seconds": round(CPU_SAMPLE_BUFFER * CPU_SAMPLE_INTERVAL),
        "reason": None if cpu_now else "CPU counters could not be sampled (/proc/stat unreadable or sampler not yet warmed up)",
    }
    return capabilities



def _parse_file_log(raw: str, path: str, inode: int, offset: int) -> dict[str, Any]:
    data: dict[str, Any] = {}
    syslog_match = re.match(r"^(?:<(\d+)>)?([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+([A-Za-z0-9_.-]+)(?:\[(\d+)\])?:\s*(.*)$", raw)
    try:
        candidate = json.loads(raw)
        if isinstance(candidate, dict):
            data = candidate
    except json.JSONDecodeError:
        pass
    if syslog_match and not data:
        priority_value, timestamp_text, service_text, pid_text, message_text = syslog_match.groups()
        data = {"message": message_text, "service": service_text, "pid": pid_text}
        if priority_value is not None:
            data["priority"] = int(priority_value) % 8
        try:
            event_datetime = datetime.strptime(f"{datetime.now(timezone.utc).year} {timestamp_text}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            data["timestamp"] = event_datetime.isoformat()
        except ValueError:
            pass
    message = str(data.get("message") or data.get("msg") or raw.strip())
    raw_level = data.get("severity")
    if raw_level is None:
        raw_level = data.get("level")
    if raw_level is None:
        raw_level = data.get("priority", "info")
    level = str(raw_level).lower()
    if level.isdigit():
        level = {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning", 5: "notice", 6: "info", 7: "debug"}.get(int(level), "info")
    if level == "info" and not data.get("priority"):
        severity_match = re.search(r"\b(emerg(?:ency)?|alert|crit(?:ical)?|err(?:or)?|warn(?:ing)?|notice|debug)\b", message, re.IGNORECASE)
        if severity_match:
            level = severity_match.group(1).lower()
    severity_aliases = {"warn": "warning", "err": "error", "fatal": "critical", "trace": "debug"}
    severity = severity_aliases.get(level, level)
    if severity not in {"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}:
        severity = "info"
    timestamp_raw = data.get("timestamp") or data.get("time") or data.get("@timestamp")
    event_at = time.time()
    if isinstance(timestamp_raw, str):
        try:
            parsed = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
            event_at = parsed.replace(tzinfo=timezone.utc).timestamp() if parsed.tzinfo is None else parsed.timestamp()
        except ValueError:
            pass
    elif isinstance(timestamp_raw, (int, float)):
        event_at = float(timestamp_raw) / (1_000_000 if timestamp_raw > 10_000_000_000 else 1)
    service = data.get("service") or data.get("logger") or Path(path).name
    pid = data.get("pid")
    if not pid:
        pid_match = re.search(r"\bpid=(\d+)\b", message, re.IGNORECASE) or re.search(r"\[(\d+)\]", message)
        if pid_match:
            pid = pid_match.group(1)
    fields = {key: value for key, value in data.items() if key not in {"message", "msg", "timestamp", "time", "@timestamp", "severity", "level", "priority", "service", "logger", "pid"}}
    event_hash = hashlib.sha256(f"{path}:{inode}:{offset}:{raw}".encode("utf-8", errors="replace")).hexdigest()
    return {
        "event_id": event_hash,
        "timestamp": datetime.fromtimestamp(event_at, timezone.utc).isoformat(),
        "timestamp_epoch": event_at,
        "source": Path(path).name,
        "severity": severity,
        "service": str(service)[:255],
        "pid": int(pid) if str(pid or "").isdigit() else None,
        "message": _redact_text(message)[:16_384],
        "fields": _safe_fields(fields),
        "parser": "json-line" if data else "plain-line",
    }


def _collect_application_logs(since: float, limit: int) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with _LOG_STATE_LOCK:
        for pattern in APP_LOG_GLOBS:
            for name in sorted(glob.glob(pattern, recursive=True)):
                if len(events) >= limit:
                    return events
                try:
                    path = Path(name)
                    stat = path.stat()
                    state = _LOG_OFFSETS.get(name, {})
                    offset = state.get("offset", stat.st_size) if state.get("inode") == stat.st_ino else stat.st_size
                    if stat.st_size < offset:
                        offset = 0
                    with path.open("rb") as stream:
                        stream.seek(offset)
                        while len(events) < limit:
                            start = stream.tell()
                            line = stream.readline(65_536)
                            if not line:
                                break
                            try:
                                raw = line.decode("utf-8", errors="replace").rstrip("\r\n")
                                if not raw:
                                    continue
                                event = _parse_file_log(raw, name, stat.st_ino, start)
                                severity_priority = {"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}.get(event["severity"], 6)
                                if severity_priority <= LOG_MIN_PRIORITY:
                                    events.append(event)
                            except (ValueError, TypeError):
                                continue
                        _LOG_OFFSETS[name] = {"inode": stat.st_ino, "offset": stream.tell()}
                except OSError:
                    continue
        try:
            LOG_STATE.parent.mkdir(parents=True, exist_ok=True)
            temporary = LOG_STATE.with_suffix(".tmp")
            temporary.write_text(json.dumps(_LOG_OFFSETS))
            temporary.replace(LOG_STATE)
        except OSError:
            pass
    return events


def collect_logs(since: float, limit: int) -> dict[str, Any]:
    journalctl = shutil.which("journalctl")
    paths = []
    for path in (HOST_LOG / "journal", Path("/host/run/log/journal")):
        if path.is_dir():
            paths.append(path)
    events: list[dict[str, Any]] = []
    journal_available = bool(journalctl and paths)
    status = "available" if journal_available else "unavailable"
    reason = None
    if journalctl and paths:
        successful_journals = 0
        for journal_path in paths:
            command = [journalctl, "--no-pager", "--output=json", "--since", f"@{max(0, since)}", "--lines", str(min(limit, LOG_LIMIT_MAX)), "--directory", str(journal_path)]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
                if result.returncode:
                    reason = result.stderr.strip()[:300]
                    continue
                successful_journals += 1
                for line in result.stdout.splitlines():
                    try:
                        record = json.loads(line)
                        priority = int(record.get("PRIORITY", 6))
                        if priority > LOG_MIN_PRIORITY:
                            continue
                        timestamp_us = int(record.get("__REALTIME_TIMESTAMP", "0"))
                        event_at = timestamp_us / 1_000_000 if timestamp_us else time.time()
                        cursor = str(record.get("__CURSOR") or "")
                        message = str(record.get("MESSAGE", ""))
                        source = str(record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or "systemd")
                        raw_pid = record.get("_PID") or record.get("SYSLOG_PID")
                        if not raw_pid:
                            # Extract pid=... or [pid] from message if present (e.g. kernel audit / syslog)
                            pid_match = re.search(r"\bpid=(\d+)\b", message, re.IGNORECASE) or re.search(r"\[(\d+)\]", message)
                            if pid_match:
                                raw_pid = pid_match.group(1)
                        pid_val = int(raw_pid) if str(raw_pid or "").isdigit() else None
                        safe_fields = _safe_fields({key: value for key, value in record.items() if not key.startswith("_") and key not in {"MESSAGE", "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP"}})
                        event_id = hashlib.sha256((cursor or f"{event_at}:{source}:{message}").encode()).hexdigest()
                        events.append({"event_id": event_id, "timestamp": datetime.fromtimestamp(event_at, timezone.utc).isoformat(), "timestamp_epoch": event_at, "source": source, "severity": {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning", 5: "notice", 6: "info", 7: "debug"}.get(priority, "unknown"), "service": record.get("_SYSTEMD_UNIT") or record.get("UNIT"), "pid": pid_val, "message": _redact_text(message)[:16_384], "fields": safe_fields, "parser": "systemd-journal"})
                    except (ValueError, TypeError, json.JSONDecodeError):
                        continue
            except (OSError, subprocess.TimeoutExpired) as exc:
                reason = str(exc)[:300]
        if successful_journals:
            status = "available"
        elif reason:
            status = "permission_denied"
    file_events = _collect_application_logs(since, max(0, min(limit, LOG_LIMIT_MAX) - len(events)))
    events.extend(file_events)
    if file_events and not journal_available:
        status = "available"
    events.sort(key=lambda event: event["timestamp_epoch"])
    next_since = max([since, *(event["timestamp_epoch"] for event in events)])
    payload = {"events": events[:limit], "next_since": next_since}
    if reason:
        payload["reason"] = reason
    return _status_data(payload, status)



@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/info")
def info(x_palantir_agent_token: str | None = Header(default=None)) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    return {
        "name": "PALANTIR Linux Host Collector",
        "version": APP_VERSION,
        "hostname": _host_hostname(),
        "machine_id": _host_machine_id(),
        "os": platform.platform(),
        "os_release": _read_os_release(),
        "cpu_model": _cpu_model(),
        "schema_version": 1,
    }



@app.get("/api/v1/capabilities")
def capabilities(x_palantir_agent_token: str | None = Header(default=None)) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    return {"schema_version": 1, "observed_at": _now(), "capabilities": discover_capabilities()}


@app.get("/api/v1/metrics/{category}")
def metrics(category: str, x_palantir_agent_token: str | None = Header(default=None)) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    collector = COLLECTORS.get(category)
    if collector is None:
        raise HTTPException(status_code=404, detail=f"Unknown category: {category}")
    try:
        payload = collector()
        return {"category": category, **payload}
    except Exception as exc:
        return {"category": category, **_status_data({"error": str(exc)[:300]}, "unavailable")}


@app.get("/api/v1/diagnostics")
def diagnostics(x_palantir_agent_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Why is a number missing?  Shows what the collector can actually read on this host."""
    _guard(x_palantir_agent_token)
    cpu_now = _CPU_SAMPLER.current()
    return {
        "version": APP_VERSION,
        "host_proc": str(HOST_PROC),
        "host_root": str(HOST_ROOT),
        "proc_stat_readable": bool(_read_text(HOST_PROC / "stat", 4096)),
        "host_net_namespace_readable": bool(_read_text(HOST_PROC / "1" / "net" / "dev", 4096)),
        "host_mounts_readable": bool(_read_text(HOST_PROC / "1" / "mounts", 4096)),
        "cpu_sampler": {
            "thread_alive": bool(_CPU_SAMPLER._thread and _CPU_SAMPLER._thread.is_alive()),
            "samples_buffered": _CPU_SAMPLER.count(),
            "current_cpu_pct": cpu_now["cpu_pct"] if cpu_now else None,
            "last_error": _CPU_SAMPLER.last_error,
        },
        "rate_sampler": {
            "thread_alive": bool(_RATE_SAMPLER._thread and _RATE_SAMPLER._thread.is_alive()),
            "fresh": _RATE_SAMPLER.fresh(),
            "processes_measured": len(_RATE_SAMPLER.process_rates()),
            "last_error": _RATE_SAMPLER.last_error,
        },
        "interfaces": sorted(_parse_proc_net_dev()),
        "token_configured": bool(AGENT_TOKEN),
        "sockets": {
            "docker": str(DOCKER_SOCKET) if DOCKER_SOCKET.exists() else None,
            "lxd": str(LXD_SOCKET) if LXD_SOCKET.exists() else None,
            "libvirt": str(LIBVIRT_SOCKET) if LIBVIRT_SOCKET.exists() else None,
            "dbus": next((str(path) for path in (Path("/host/run/dbus/system_bus_socket"), Path("/run/dbus/system_bus_socket")) if path.exists()), None),
        },
        "tools": {name: bool(shutil.which(name)) for name in ("busctl", "systemctl", "journalctl", "virsh", "nft")},
        "journal_dirs": [str(path) for path in (HOST_LOG / "journal", Path("/host/run/log/journal")) if path.is_dir()],
        "virtualization": _virtualization(),
    }


@app.get("/api/v1/samples/cpu")
def cpu_samples(
    since: float = Query(default=0, ge=0, description="Only samples newer than this Unix time (seconds)"),
    limit: int = Query(default=900, ge=1, le=CPU_SAMPLE_BUFFER),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Per-second total-CPU samples ({t, cpu_pct}), oldest first. `now` lets the caller correct for clock skew."""
    _guard(x_palantir_agent_token)
    samples = _CPU_SAMPLER.since(since, limit)
    return {
        "schema_version": 1,
        "status": "available" if samples or _CPU_SAMPLER.current() else "unavailable",
        "now": time.time(),
        "interval_seconds": CPU_SAMPLE_INTERVAL,
        "samples": samples,
    }


@app.get("/api/v1/logs")
def logs(
    since: float = Query(default=0, ge=0),
    limit: int = Query(default=5000, ge=1, le=5000),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    return collect_logs(since, limit)


@app.post("/api/v1/processes/{pid}/kill")
def kill_process(
    pid: int,
    signal_type: str = Query(default="SIGTERM", pattern="^(SIGTERM|SIGKILL|15|9)$"),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        # Without a token anybody who can reach port 20000 could kill any host process.
        raise HTTPException(status_code=403, detail="Process control is disabled: start the collector with PALANTIR_AGENT_TOKEN set")
    sig = signal.SIGKILL if signal_type in {"SIGKILL", "9"} else signal.SIGTERM
    # Prevent accidental suicide or killing PID 1
    if pid <= 1:
        raise HTTPException(status_code=400, detail="Cannot terminate PID <= 1")
    try:
        os.kill(pid, sig)
        return {"success": True, "pid": pid, "signal": "SIGKILL" if sig == signal.SIGKILL else "SIGTERM"}
    except ProcessLookupError:
        raise HTTPException(status_code=404, detail=f"Process {pid} not found")
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=f"Permission denied killing process {pid}: {exc}")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to kill process {pid}: {exc}")


@app.post("/api/v1/containers/{container_id}/stop")
def stop_container(
    container_id: str,
    timeout_seconds: int = Query(default=10, ge=0, le=60),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        raise HTTPException(status_code=403, detail="Container control is disabled: start the collector with PALANTIR_AGENT_TOKEN set")
    if not DOCKER_SOCKET.exists() or not DOCKER_SOCKET.is_socket():
        raise HTTPException(status_code=400, detail="Docker/Podman socket is not mounted or available")

    clean_id = container_id.strip()
    if not clean_id or not re.match(r"^[a-zA-Z0-9_.-]+$", clean_id):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    # Collect active container host PIDs before stopping it
    stopped_pids: list[int] = []
    try:
        top_status, top_body = _unix_request(DOCKER_SOCKET, f"/containers/{clean_id}/top", timeout=3.0)
        if top_status == 200:
            top_data = json.loads(top_body)
            titles = [str(t).upper() for t in top_data.get("Titles", [])]
            pid_idx = titles.index("PID") if "PID" in titles else 1
            for proc in top_data.get("Processes", []):
                if len(proc) > pid_idx:
                    try:
                        p_val = int(proc[pid_idx])
                        if p_val > 1:
                            stopped_pids.append(p_val)
                    except (ValueError, TypeError):
                        pass
    except Exception:
        pass

    try:
        status, body = _unix_request(
            DOCKER_SOCKET,
            f"/containers/{clean_id}/stop?t={timeout_seconds}",
            timeout=float(timeout_seconds + 5),
            method="POST",
        )
        if status in {204, 304}:
            return {
                "success": True,
                "container_id": clean_id,
                "status": "stopped" if status == 204 else "already_stopped",
                "stopped_pids": stopped_pids,
            }
        if status == 404:
            raise HTTPException(status_code=404, detail=f"Container {clean_id} not found")
        raise HTTPException(status_code=500, detail=f"Docker API error ({status}): {body.decode(errors='replace')[:200]}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to stop container {clean_id}: {exc}")


@app.post("/api/v1/vms/{vm_id}/stop")
def stop_vm(
    vm_id: str,
    force: bool = Query(default=False),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        raise HTTPException(status_code=403, detail="VM control is disabled: start the collector with PALANTIR_AGENT_TOKEN set")

    target = vm_id.strip()
    if not target or not re.match(r"^[a-zA-Z0-9_.-]+$", target):
        raise HTTPException(status_code=400, detail="Invalid VM identifier")

    virsh = shutil.which("virsh")
    if virsh and LIBVIRT_SOCKET.exists():
        uri = f"qemu+unix:///system?socket={LIBVIRT_SOCKET}"
        action = "destroy" if force else "shutdown"
        res = subprocess.run([virsh, "--connect", uri, action, target], capture_output=True, text=True, timeout=10, check=False)
        if res.returncode == 0:
            return {"success": True, "vm_id": target, "action": action, "runtime": "libvirt"}

    if PROXMOX_API_URL and PROXMOX_API_TOKEN:
        headers = {"Authorization": f"PVEAPIToken={PROXMOX_API_TOKEN}"}
        verify: str | bool = False if PROXMOX_INSECURE_TLS else (PROXMOX_CA_CERT or True)
        subpath = "stop" if force else "shutdown"
        try:
            nodes = httpx.get(f"{PROXMOX_API_URL}/api2/json/nodes", headers=headers, verify=verify, timeout=5.0)
            if nodes.status_code == 200:
                for node_obj in nodes.json().get("data", []):
                    n_name = node_obj.get("node")
                    for r_type in ("qemu", "lxc"):
                        r_post = httpx.post(
                            f"{PROXMOX_API_URL}/api2/json/nodes/{n_name}/{r_type}/{target}/status/{subpath}",
                            headers=headers,
                            verify=verify,
                            timeout=10.0,
                        )
                        if r_post.status_code in {200, 204}:
                            return {"success": True, "vm_id": target, "action": subpath, "runtime": f"proxmox-{r_type}"}
        except Exception:
            pass

    raise HTTPException(status_code=404, detail=f"VM '{target}' could not be stopped (not found or hypervisor unreachable)")


def _demux_docker_logs(raw: bytes) -> str:
    lines: list[str] = []
    i = 0
    n = len(raw)
    while i + 8 <= n:
        stream_type = raw[i]
        if stream_type in (1, 2) and raw[i + 1 : i + 4] == b"\x00\x00\x00":
            size = int.from_bytes(raw[i + 4 : i + 8], byteorder="big")
            i += 8
            if i + size <= n:
                chunk = raw[i : i + size].decode(errors="replace")
                lines.append(chunk)
                i += size
                continue
            else:
                chunk = raw[i:].decode(errors="replace")
                lines.append(chunk)
                break
        else:
            return raw.decode(errors="replace")
    return "".join(lines) if lines else raw.decode(errors="replace")


@app.post("/api/v1/containers/{container_id}/start")
def start_container(
    container_id: str,
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        raise HTTPException(status_code=403, detail="Container control is disabled: start the collector with PALANTIR_AGENT_TOKEN set")
    if not DOCKER_SOCKET.exists() or not DOCKER_SOCKET.is_socket():
        raise HTTPException(status_code=400, detail="Docker/Podman socket is not mounted or available")

    clean_id = container_id.strip()
    if not clean_id or not re.match(r"^[a-zA-Z0-9_.-]+$", clean_id):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    try:
        status, body = _unix_request(
            DOCKER_SOCKET,
            f"/containers/{clean_id}/start",
            timeout=15.0,
            method="POST",
        )
        if status in {204, 304}:
            return {
                "success": True,
                "container_id": clean_id,
                "status": "started" if status == 204 else "already_started",
            }
        if status == 404:
            raise HTTPException(status_code=404, detail=f"Container {clean_id} not found")
        raise HTTPException(status_code=500, detail=f"Docker API error ({status}): {body.decode(errors='replace')[:200]}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start container {clean_id}: {exc}")


@app.post("/api/v1/containers/{container_id}/restart")
def restart_container(
    container_id: str,
    timeout_seconds: int = Query(default=10, ge=0, le=60),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        raise HTTPException(status_code=403, detail="Container control is disabled: start the collector with PALANTIR_AGENT_TOKEN set")
    if not DOCKER_SOCKET.exists() or not DOCKER_SOCKET.is_socket():
        raise HTTPException(status_code=400, detail="Docker/Podman socket is not mounted or available")

    clean_id = container_id.strip()
    if not clean_id or not re.match(r"^[a-zA-Z0-9_.-]+$", clean_id):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    try:
        status, body = _unix_request(
            DOCKER_SOCKET,
            f"/containers/{clean_id}/restart?t={timeout_seconds}",
            timeout=float(timeout_seconds + 10),
            method="POST",
        )
        if status in {204, 304}:
            return {
                "success": True,
                "container_id": clean_id,
                "status": "restarted",
            }
        if status == 404:
            raise HTTPException(status_code=404, detail=f"Container {clean_id} not found")
        raise HTTPException(status_code=500, detail=f"Docker API error ({status}): {body.decode(errors='replace')[:200]}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to restart container {clean_id}: {exc}")


@app.get("/api/v1/containers/{container_id}/logs")
def get_container_logs(
    container_id: str,
    tail: int = Query(default=200, ge=1, le=5000),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        raise HTTPException(status_code=403, detail="Container inspection is disabled: start the collector with PALANTIR_AGENT_TOKEN set")
    if not DOCKER_SOCKET.exists() or not DOCKER_SOCKET.is_socket():
        raise HTTPException(status_code=400, detail="Docker/Podman socket is not mounted or available")

    clean_id = container_id.strip()
    if not clean_id or not re.match(r"^[a-zA-Z0-9_.-]+$", clean_id):
        raise HTTPException(status_code=400, detail="Invalid container identifier")

    try:
        status, body = _unix_request(
            DOCKER_SOCKET,
            f"/containers/{clean_id}/logs?stdout=1&stderr=1&tail={tail}&timestamps=0",
            timeout=10.0,
            method="GET",
        )
        if status == 200:
            clean_text = _demux_docker_logs(body)
            return {
                "success": True,
                "container_id": clean_id,
                "tail": tail,
                "logs": clean_text,
            }
        if status == 404:
            raise HTTPException(status_code=404, detail=f"Container {clean_id} not found")
        raise HTTPException(status_code=500, detail=f"Docker API error ({status}): {body.decode(errors='replace')[:200]}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs for container {clean_id}: {exc}")


@app.post("/api/v1/vms/{vm_id}/start")
def start_vm(
    vm_id: str,
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        raise HTTPException(status_code=403, detail="VM control is disabled: start the collector with PALANTIR_AGENT_TOKEN set")

    target = vm_id.strip()
    if not target or not re.match(r"^[a-zA-Z0-9_.-]+$", target):
        raise HTTPException(status_code=400, detail="Invalid VM identifier")

    virsh = shutil.which("virsh")
    if virsh and LIBVIRT_SOCKET.exists():
        uri = f"qemu+unix:///system?socket={LIBVIRT_SOCKET}"
        res = subprocess.run([virsh, "--connect", uri, "start", target], capture_output=True, text=True, timeout=10, check=False)
        if res.returncode == 0:
            return {"success": True, "vm_id": target, "action": "start", "runtime": "libvirt"}

    if PROXMOX_API_URL and PROXMOX_API_TOKEN:
        headers = {"Authorization": f"PVEAPIToken={PROXMOX_API_TOKEN}"}
        verify: str | bool = False if PROXMOX_INSECURE_TLS else (PROXMOX_CA_CERT or True)
        try:
            nodes = httpx.get(f"{PROXMOX_API_URL}/api2/json/nodes", headers=headers, verify=verify, timeout=5.0)
            if nodes.status_code == 200:
                for node_obj in nodes.json().get("data", []):
                    n_name = node_obj.get("node")
                    for r_type in ("qemu", "lxc"):
                        r_post = httpx.post(
                            f"{PROXMOX_API_URL}/api2/json/nodes/{n_name}/{r_type}/{target}/status/start",
                            headers=headers,
                            verify=verify,
                            timeout=10.0,
                        )
                        if r_post.status_code in {200, 204}:
                            return {"success": True, "vm_id": target, "action": "start", "runtime": f"proxmox-{r_type}"}
        except Exception:
            pass

    raise HTTPException(status_code=404, detail=f"VM '{target}' could not be started (not found or hypervisor unreachable)")


@app.post("/api/v1/vms/{vm_id}/restart")
def restart_vm(
    vm_id: str,
    force: bool = Query(default=False),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    if not AGENT_TOKEN and not ALLOW_ANONYMOUS_KILL:
        raise HTTPException(status_code=403, detail="VM control is disabled: start the collector with PALANTIR_AGENT_TOKEN set")

    target = vm_id.strip()
    if not target or not re.match(r"^[a-zA-Z0-9_.-]+$", target):
        raise HTTPException(status_code=400, detail="Invalid VM identifier")

    virsh = shutil.which("virsh")
    if virsh and LIBVIRT_SOCKET.exists():
        uri = f"qemu+unix:///system?socket={LIBVIRT_SOCKET}"
        action = "reset" if force else "reboot"
        res = subprocess.run([virsh, "--connect", uri, action, target], capture_output=True, text=True, timeout=10, check=False)
        if res.returncode == 0:
            return {"success": True, "vm_id": target, "action": action, "runtime": "libvirt"}

    if PROXMOX_API_URL and PROXMOX_API_TOKEN:
        headers = {"Authorization": f"PVEAPIToken={PROXMOX_API_TOKEN}"}
        verify: str | bool = False if PROXMOX_INSECURE_TLS else (PROXMOX_CA_CERT or True)
        try:
            nodes = httpx.get(f"{PROXMOX_API_URL}/api2/json/nodes", headers=headers, verify=verify, timeout=5.0)
            if nodes.status_code == 200:
                for node_obj in nodes.json().get("data", []):
                    n_name = node_obj.get("node")
                    for r_type in ("qemu", "lxc"):
                        r_post = httpx.post(
                            f"{PROXMOX_API_URL}/api2/json/nodes/{n_name}/{r_type}/{target}/status/reboot",
                            headers=headers,
                            verify=verify,
                            timeout=10.0,
                        )
                        if r_post.status_code in {200, 204}:
                            return {"success": True, "vm_id": target, "action": "reboot", "runtime": f"proxmox-{r_type}"}
        except Exception:
            pass

    raise HTTPException(status_code=404, detail=f"VM '{target}' could not be restarted (not found or hypervisor unreachable)")


_start_samplers()
