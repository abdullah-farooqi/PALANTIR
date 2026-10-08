"""Small Linux host collector exposed to the central pull worker."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import glob
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
import httpx
from fastapi import FastAPI, Header, HTTPException, Query

APP_VERSION = "0.1.0"
HOST_PROC = Path(os.getenv("HOST_PROC", "/host/proc"))
HOST_SYS = Path(os.getenv("HOST_SYS", "/host/sys"))
HOST_ROOT = Path(os.getenv("HOST_ROOT", "/host"))
HOST_LOG = Path(os.getenv("HOST_LOG", "/host/var/log"))
AGENT_TOKEN = os.getenv("PALANTIR_AGENT_TOKEN", "")
LOG_MIN_PRIORITY = int(os.getenv("LOG_MIN_PRIORITY", "7"))
LOG_LIMIT_MAX = int(os.getenv("LOG_LIMIT_MAX", "5000"))
APP_LOG_GLOBS = [item for item in os.getenv("APP_LOG_GLOBS", "/host/var/log/**/*.log").split(",") if item]
DOCKER_SOCKET = Path(os.getenv("DOCKER_SOCKET", "/host/run/docker.sock"))
LXD_SOCKET = Path(os.getenv("LXD_SOCKET", "/host/var/lib/lxd/unix.socket"))
KUBERNETES_API_URL = os.getenv("KUBERNETES_API_URL", "").rstrip("/")
KUBERNETES_TOKEN = os.getenv("KUBERNETES_TOKEN", "")
KUBERNETES_CA_CERT = os.getenv("KUBERNETES_CA_CERT", "")
PROXMOX_API_URL = os.getenv("PROXMOX_API_URL", "").rstrip("/")
PROXMOX_API_TOKEN = os.getenv("PROXMOX_API_TOKEN", "")
PROXMOX_CA_CERT = os.getenv("PROXMOX_CA_CERT", "")
LOG_STATE = Path(os.getenv("LOG_STATE", "/var/lib/palantir-agent/log-offsets.json"))
SENSITIVE_KEY = re.compile(r"password|passwd|token|secret|api[_-]?key|authorization|credential", re.IGNORECASE)
SENSITIVE_VALUE = re.compile(r"(?i)((?:password|passwd|token|secret|api[_-]?key|authorization)(?:\s*[:=]\s*))(?:bearer\s+)?(?:['\"])?[^\s,;'\"]+")
psutil.PROCFS_PATH = str(HOST_PROC)
_LOG_STATE_LOCK = threading.Lock()
try:
    _LOG_OFFSETS: dict[str, dict[str, int]] = json.loads(LOG_STATE.read_text())
except (OSError, json.JSONDecodeError):
    _LOG_OFFSETS = {}

app = FastAPI(title="PALANTIR Linux Host Collector", version=APP_VERSION)

CATEGORIES = ("system", "storage", "network", "services", "processes", "connections", "containers", "vms")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    if AGENT_TOKEN and token != AGENT_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid agent token")


def _read_text(path: Path, limit: int = 2_000_000) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            return stream.read(limit)
    except (OSError, PermissionError):
        return ""


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
    return [
        {
            "device": name,
            "read_bytes": item.read_bytes,
            "write_bytes": item.write_bytes,
            "read_count": item.read_count,
            "write_count": item.write_count,
            "read_time_ms": item.read_time,
            "write_time_ms": item.write_time,
        }
        for name, item in sorted((stats or {}).items())
    ]


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


def collect_system() -> dict[str, Any]:
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    load = os.getloadavg() if hasattr(os, "getloadavg") else (None, None, None)
    
    # Per-core and total CPU telemetry
    cpu_total = psutil.cpu_percent(interval=0.1)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    times = psutil.cpu_times_percent(interval=None)
    cpu_times_dict = {
        "user": getattr(times, "user", 0.0),
        "system": getattr(times, "system", 0.0),
        "idle": getattr(times, "idle", 0.0),
        "iowait": getattr(times, "iowait", 0.0),
        "irq": getattr(times, "irq", 0.0),
        "softirq": getattr(times, "softirq", 0.0),
        "steal": getattr(times, "steal", 0.0),
    }

    vmstat = {}
    for line in _read_text(HOST_PROC / "vmstat", 256_000).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in {"oom_kill", "pgmajfault", "pswpin", "pswpout"}:
            try:
                vmstat[parts[0]] = int(parts[1])
            except ValueError:
                pass
    meminfo = {}
    for line in _read_text(HOST_PROC / "meminfo", 256_000).splitlines():
        parts = line.split(":")
        if len(parts) == 2:
            k = parts[0].strip()
            v_str = parts[1].strip().split()[0]
            if v_str.isdigit():
                meminfo[k] = int(v_str) * 1024  # Convert kB to bytes

    buffers_bytes = getattr(mem, "buffers", meminfo.get("Buffers", 0))
    cached_bytes = getattr(mem, "cached", meminfo.get("Cached", 0))
    active_bytes = getattr(mem, "active", meminfo.get("Active", 0))
    inactive_bytes = getattr(mem, "inactive", meminfo.get("Inactive", 0))
    slab_bytes = getattr(mem, "slab", meminfo.get("Slab", 0))

    os_release = {}
    for os_file in [HOST_ROOT / "etc/os-release", Path("/etc/os-release")]:
        if os_file.exists():
            for line in _read_text(os_file, 16_000).splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    os_release[k.strip()] = v.strip().strip('"')
            break

    return _status_data({
        "cpu_count": psutil.cpu_count(),
        "cpu_logical_count": psutil.cpu_count(logical=True),
        "cpu_pct": cpu_total,
        "cpu_cores_pct": per_core,
        "cpu_times": cpu_times_dict,
        "memory": {
            "total_bytes": mem.total,
            "available_bytes": mem.available,
            "used_bytes": mem.used,
            "buffers_bytes": buffers_bytes,
            "cached_bytes": cached_bytes,
            "active_bytes": active_bytes,
            "inactive_bytes": inactive_bytes,
            "slab_bytes": slab_bytes,
            "percent": mem.percent,
        },
        "swap": {"total_bytes": swap.total, "used_bytes": swap.used, "percent": swap.percent},
        "load_average": list(load),
        "vmstat": vmstat,
        "os_release": os_release,
    })


def collect_storage() -> dict[str, Any]:
    filesystems = []
    seen: set[str] = set()

    SKIP_FSTYPES = {
        "squashfs", "overlay", "tmpfs", "devtmpfs", "proc", "sysfs", "cgroup",
        "cgroup2", "binfmt_misc", "efivarfs", "bpf", "pstore", "fusectl",
        "configfs", "debugfs", "tracefs", "autofs", "devpts", "mqueue"
    }

    # 1. Always attempt physical host root first
    for root_candidate in [HOST_ROOT, Path("/")]:
        if root_candidate.exists():
            try:
                usage = shutil.disk_usage(root_candidate)
                filesystems.append({
                    "device": "/dev/root",
                    "mountpoint": "/",
                    "filesystem": "ext4",
                    "options": "rw",
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent": round(usage.used / usage.total * 100, 2) if usage.total else 0,
                    "status": "available",
                })
                seen.add("/")
                break
            except OSError:
                pass

    # 2. Add additional physical mount points if present
    try:
        partitions = psutil.disk_partitions(all=True)
    except (OSError, RuntimeError):
        partitions = []

    for part in partitions:
        mp = part.mountpoint
        clean_mp = mp[5:] if mp.startswith("/host/") else mp
        if clean_mp == "/host":
            clean_mp = "/"
        if clean_mp in seen or part.fstype in SKIP_FSTYPES:
            continue
        if clean_mp.startswith(("/proc", "/sys", "/dev", "/run", "/snap", "/etc", "/etc/")):
            continue

        target_path = Path(mp) if mp.startswith("/host/") else (HOST_ROOT / mp.lstrip("/"))
        if not target_path.exists():
            target_path = Path(mp)

        try:
            usage = shutil.disk_usage(target_path)
            seen.add(clean_mp)
            filesystems.append({
                "device": part.device or clean_mp,
                "mountpoint": clean_mp,
                "filesystem": part.fstype,
                "options": part.opts,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent": round(usage.used / usage.total * 100, 2) if usage.total else 0,
                "status": "available",
            })
        except OSError:
            continue

    mdstat = _read_text(HOST_PROC / "mdstat", 256_000)
    raid_arrays = _parse_mdstat(mdstat)
    return _status_data({
        "filesystems": filesystems,
        "disk_io": _disk_io(),
        "raid": {"detected": bool(raid_arrays), "arrays": raid_arrays, "mdstat_raw": mdstat},
    }, "available" if filesystems or mdstat else "partial")


def _parse_proc_net_dev() -> dict[str, dict[str, int]]:
    dev_path = HOST_PROC / "net/dev"
    if not dev_path.exists():
        dev_path = Path("/proc/net/dev")
    interfaces = {}
    content = _read_text(dev_path, 500_000)
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
    protocols = {}
    pending_headers: dict[str, list[str]] = {}
    for line in _read_text(HOST_PROC / "net/snmp", 256_000).splitlines():
        fields = line.split()
        if len(fields) > 1 and fields[0].endswith(":"):
            protocol = fields[0][:-1]
            columns = fields[1:]
            if protocol not in pending_headers:
                pending_headers[protocol] = columns
                continue
            names = pending_headers.pop(protocol)
            protocols[protocol] = {
                name: int(value) if value.isdigit() else value
                for name, value in zip(names, columns)
            }
    return _status_data({"interfaces": interfaces, "protocol_counters": protocols, "firewall": _firewall_state()})


def _firewall_state() -> dict[str, Any]:
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


def collect_processes() -> dict[str, Any]:
    rows = []
    for proc in psutil.process_iter(attrs=["pid", "name", "status", "memory_info", "num_threads", "username", "create_time", "cpu_times"]):
        try:
            item = proc.info
            memory = item.get("memory_info")
            cpu_times = item.get("cpu_times")
            rows.append({
                "pid": item.get("pid"), "name": item.get("name"), "status": item.get("status"),
                "rss_bytes": memory.rss if memory else None, "threads": item.get("num_threads"),
                "username": item.get("username"), "started_at": item.get("create_time"),
                "cpu_time_seconds": (cpu_times.user + cpu_times.system) if cpu_times else None,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    rows.sort(key=lambda row: row.get("rss_bytes") or 0, reverse=True)
    oom = {}
    for line in _read_text(HOST_PROC / "vmstat", 256_000).splitlines():
        key, _, value = line.partition(" ")
        if key in {"oom_kill", "oom_reaper"}:
            try:
                oom[key] = int(value.strip())
            except ValueError:
                pass
    return _status_data({"process_count": len(rows), "top_by_rss": rows[:100], "oom_counters": oom})


def collect_connections() -> dict[str, Any]:
    rows = []
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            for conn in proc.net_connections(kind="inet"):
                if not conn.laddr:
                    continue
                rows.append({
                    "pid": proc.pid, "process": proc.info.get("name"),
                    "family": "ipv6" if conn.family == socket.AF_INET6 else "ipv4",
                    "type": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                    "local_address": conn.laddr.ip, "local_port": conn.laddr.port,
                    "remote_address": conn.raddr.ip if conn.raddr else None,
                    "remote_port": conn.raddr.port if conn.raddr else None,
                    "state": conn.status,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue
    rows = rows[:5000]
    return _status_data({"count": len(rows), "truncated": len(rows) >= 5000, "sockets": rows})


def _systemd_services() -> tuple[list[dict[str, str]], str]:
    systemctl = shutil.which("systemctl")
    bus = Path("/host/run/dbus/system_bus_socket")
    if not systemctl or not bus.exists():
        return [], "unavailable"
    try:
        result = subprocess.run(
            [systemctl, "--no-pager", "--all", "--type=service", "--output=json", "list-units"],
            capture_output=True, text=True, timeout=5, check=False,
            env={**os.environ, "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/host/run/dbus/system_bus_socket"},
        )
        if result.returncode:
            return [], "permission_denied"
        parsed = json.loads(result.stdout)
        if isinstance(parsed, dict):
            parsed = parsed.get("units", [])
        if not isinstance(parsed, list):
            return [], "unavailable"
        return [
            {"unit": str(row.get("unit", "")), "load": str(row.get("load", "")), "active": str(row.get("active", "")), "sub": str(row.get("sub", "")), "description": str(row.get("description", ""))}
            for row in parsed if isinstance(row, dict) and str(row.get("unit", "")).endswith(".service")
        ], "available"
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return [], "unavailable"


def collect_services() -> dict[str, Any]:
    services, status = _systemd_services()
    return _status_data({"manager": "systemd", "services": services}, status)


def _docker_request(path: str) -> Any:
    if not DOCKER_SOCKET.exists() or not DOCKER_SOCKET.is_socket():
        raise FileNotFoundError("Docker socket not mounted")
    import http.client

    class UnixConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(3)
            self.sock.connect(str(DOCKER_SOCKET))

    conn = UnixConnection("localhost", timeout=3)
    conn.request("GET", path, headers={"Host": "localhost"})
    response = conn.getresponse()
    body = response.read(2_000_000)
    conn.close()
    if response.status != 200:
        raise OSError(f"Docker API returned HTTP {response.status}")
    return json.loads(body)


def _container_stats(container_id: str) -> dict[str, Any]:
    try:
        stats = _docker_request(f"/containers/{container_id}/stats?stream=false")
        memory = stats.get("memory_stats", {})
        cpu = stats.get("cpu_stats", {})
        previous = stats.get("precpu_stats", {})
        cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - previous.get("cpu_usage", {}).get("total_usage", 0)
        system_delta = cpu.get("system_cpu_usage", 0) - previous.get("system_cpu_usage", 0)
        online = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage", [])) or 1
        cpu_pct = (cpu_delta / system_delta * online * 100) if system_delta > 0 else None
        return {"memory_usage_bytes": memory.get("usage"), "memory_limit_bytes": memory.get("limit"), "cpu_percent": cpu_pct}
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}


def collect_containers() -> dict[str, Any]:
    sources: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    docker_status = "unavailable"
    try:
        containers = _docker_request("/containers/json?all=1")
        docker_status = "available"
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        containers = []
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
        rows.append({"runtime": "docker", "id": cid[:12], "name": (container.get("Names") or [""])[0].lstrip("/"), "image": container.get("Image"), "state": container.get("State"), "status": container.get("Status"), "labels": safe_labels, "metrics": metrics})
    sources["docker"] = {
        "status": docker_status,
        "count": len(containers),
        "stats_count": len(active),
        "stats_truncated": len([item for item in containers if item.get("State") == "running"]) > len(active),
    }

    lxd_path = LXD_SOCKET if LXD_SOCKET.exists() else Path("/host/run/lxd/unix.socket")
    try:
        lxd = _unix_http_get(lxd_path, "/1.0/instances?recursion=1")
        instances = lxd.get("metadata", []) if isinstance(lxd, dict) else []
        for item in instances:
            rows.append({"runtime": "lxd", "name": item.get("name"), "type": item.get("type"), "status": item.get("status"), "architecture": item.get("architecture"), "profiles": item.get("profiles", []), "config": {key: value for key, value in (item.get("config") or {}).items() if key.startswith("limits.")}})
        sources["lxd"] = {"status": "available", "count": len(instances)}
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        sources["lxd"] = {"status": "unavailable"}

    kube = _collect_kubernetes()
    if kube["status"] == "available":
        rows.extend(kube["pods"])
    sources["kubernetes"] = {"status": kube["status"], "reason": kube.get("reason"), "count": len(kube.get("pods", []))}
    source_statuses = [item.get("status") for item in sources.values()]
    status = "available" if "available" in source_statuses else "unavailable"
    return _status_data({"containers": rows, "sources": sources}, status)


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
    import http.client

    class UnixConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(3)
            self.sock.connect(str(path))

    connection = UnixConnection("localhost", timeout=3)
    connection.request("GET", request_path)
    response = connection.getresponse()
    content = response.read(2_000_000)
    connection.close()
    if response.status != 200:
        raise OSError(f"runtime API returned HTTP {response.status}")
    payload = json.loads(content)
    if isinstance(payload, dict) and payload.get("type") == "async":
        operation = payload.get("operation", "").rstrip("/")
        if operation:
            return _unix_http_get(path, operation + "/wait")
    return payload


def collect_vms() -> dict[str, Any]:
    proxmox = _collect_proxmox()
    virsh = shutil.which("virsh")
    libvirt_socket = Path("/host/run/libvirt/libvirt-sock")
    if not virsh or not libvirt_socket.exists():
        if proxmox["status"] == "available":
            return _status_data({"sources": {"proxmox": proxmox}, "vms": proxmox.get("vms", [])})
        return _status_data({"runtime": "libvirt", "vms": [], "proxmox": proxmox, "reason": "libvirt client or host namespace unavailable"}, "unavailable")
    try:
        uri = "qemu+unix:///system?socket=/host/run/libvirt/libvirt-sock"
        result = subprocess.run([virsh, "--connect", uri, "list", "--all", "--name"], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode:
            if proxmox["status"] == "available":
                return _status_data({"sources": {"proxmox": proxmox}, "vms": proxmox.get("vms", [])})
            return _status_data({"runtime": "libvirt", "vms": [], "reason": result.stderr.strip()[:300]}, "unavailable")
        names = [name for name in result.stdout.splitlines() if name.strip()]
        vms = []
        for name in names[:500]:
            info = subprocess.run([virsh, "--connect", uri, "dominfo", name], capture_output=True, text=True, timeout=5, check=False)
            parsed = {}
            for line in info.stdout.splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    parsed[key.strip().lower().replace(" ", "_")] = value.strip()
            vms.append({"name": name, "state": parsed.get("state"), "cpu_count": parsed.get("cpu(s)"), "max_memory": parsed.get("max_memory"), "used_memory": parsed.get("used_memory")})
        return _status_data({"sources": {"libvirt": {"status": "available", "count": len(vms)}, "proxmox": proxmox}, "vms": vms + proxmox.get("vms", [])})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _status_data({"runtime": "libvirt", "vms": [], "reason": str(exc)[:300]}, "unavailable")


def _collect_proxmox() -> dict[str, Any]:
    if not PROXMOX_API_URL or not PROXMOX_API_TOKEN:
        return {"status": "not_configured", "vms": [], "reason": "Proxmox API URL/token not configured"}
    headers = {"Authorization": f"PVEAPIToken={PROXMOX_API_TOKEN}"}
    verify: str | bool = PROXMOX_CA_CERT or True
    try:
        nodes = httpx.get(f"{PROXMOX_API_URL}/api2/json/nodes", headers=headers, verify=verify, timeout=5.0)
        nodes.raise_for_status()
        vms = []
        for node in nodes.json().get("data", []):
            node_name = node.get("node")
            for runtime, endpoint in (("qemu", "qemu"), ("lxc", "lxc")):
                response = httpx.get(f"{PROXMOX_API_URL}/api2/json/nodes/{node_name}/{endpoint}", headers=headers, verify=verify, timeout=5.0)
                response.raise_for_status()
                for item in response.json().get("data", []):
                    vms.append({"runtime": "proxmox-" + runtime, "node": node_name, "vmid": item.get("vmid"), "name": item.get("name"), "status": item.get("status"), "cpu": item.get("cpu"), "memory_bytes": item.get("mem"), "max_memory_bytes": item.get("maxmem")})
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
    lxd_path = LXD_SOCKET if LXD_SOCKET.exists() else Path("/host/run/lxd/unix.socket")
    capabilities["containers"] = {
        "status": "available" if ((DOCKER_SOCKET.exists() and DOCKER_SOCKET.is_socket()) or (lxd_path.exists() and lxd_path.is_socket()) or (KUBERNETES_API_URL and KUBERNETES_TOKEN)) else "unavailable",
        "sources": {"docker": DOCKER_SOCKET.exists() and DOCKER_SOCKET.is_socket(), "lxd": lxd_path.exists() and lxd_path.is_socket(), "kubernetes": bool(KUBERNETES_API_URL and KUBERNETES_TOKEN)},
        "reason": None if ((DOCKER_SOCKET.exists() and DOCKER_SOCKET.is_socket()) or (lxd_path.exists() and lxd_path.is_socket()) or (KUBERNETES_API_URL and KUBERNETES_TOKEN)) else "No Docker/LXD socket or Kubernetes API credentials are configured",
    }
    containerd_socket = Path("/host/run/containerd/containerd.sock")
    capabilities["containerd"] = {
        "status": "not_configured" if containerd_socket.exists() else "unavailable",
        "reason": "containerd CRI collection is not configured" if containerd_socket.exists() else "containerd socket not present",
    }
    legacy_lxc = Path("/host/var/lib/lxc")
    capabilities["lxc"] = {
        "status": "not_configured" if legacy_lxc.is_dir() else "unavailable",
        "reason": "legacy LXC adapter is not configured" if legacy_lxc.is_dir() else "legacy LXC is not present",
    }
    capabilities["vms"] = {
        "status": "available" if ((shutil.which("virsh") and Path("/host/run/libvirt/libvirt-sock").exists()) or (PROXMOX_API_URL and PROXMOX_API_TOKEN)) else "unavailable",
        "sources": {"libvirt": bool(shutil.which("virsh") and Path("/host/run/libvirt/libvirt-sock").exists()), "proxmox": bool(PROXMOX_API_URL and PROXMOX_API_TOKEN)},
        "reason": None if ((shutil.which("virsh") and Path("/host/run/libvirt/libvirt-sock").exists()) or (PROXMOX_API_URL and PROXMOX_API_TOKEN)) else "libvirt socket or Proxmox API credentials are unavailable",
    }
    capabilities["firewall"] = _firewall_state()
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
                        safe_fields = _safe_fields({key: value for key, value in record.items() if not key.startswith("_") and key not in {"MESSAGE", "__CURSOR", "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP"}})
                        event_id = hashlib.sha256((cursor or f"{event_at}:{source}:{message}").encode()).hexdigest()
                        events.append({"event_id": event_id, "timestamp": datetime.fromtimestamp(event_at, timezone.utc).isoformat(), "timestamp_epoch": event_at, "source": source, "severity": {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning", 5: "notice", 6: "info", 7: "debug"}.get(priority, "unknown"), "service": record.get("_SYSTEMD_UNIT") or record.get("UNIT"), "pid": record.get("_PID"), "message": _redact_text(message)[:16_384], "fields": safe_fields, "parser": "systemd-journal"})
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
    return {"name": "PALANTIR Linux Host Collector", "version": APP_VERSION, "hostname": socket.gethostname(), "os": platform.platform(), "schema_version": 1}


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


@app.get("/api/v1/logs")
def logs(
    since: float = Query(default=0, ge=0),
    limit: int = Query(default=5000, ge=1, le=5000),
    x_palantir_agent_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _guard(x_palantir_agent_token)
    return collect_logs(since, limit)
