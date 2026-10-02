import math
import uuid
from typing import Dict, Any, List, Optional, Set


def is_valid_guid(s: str) -> bool:
    """Check if string is a valid UUID/GUID."""
    if not s or not isinstance(s, str):
        return False
    try:
        uuid.UUID(s)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _finite_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _nonnegative_float(value: Any) -> Optional[float]:
    number = _finite_float(value)
    if number is None or number < 0.0:
        return None
    return number


def _process_value(value: Any) -> Optional[float]:
    if value is None:
        return 0.0
    return _nonnegative_float(value)


def strip_machine_guid(key: str) -> str:
    """
    Strips Netdata machine GUID suffix @<uuid>
    (e.g., system.cpu@87f56850-57c0-43b7-a6e2-13c37aaaa009 -> system.cpu,
     app.firefox_mem_usage@87f56850-... -> app.firefox_mem_usage,
     net.eth0@87f56850-... -> net.eth0).
    If no @ or no GUID present, returns the key as-is.
    """
    if not isinstance(key, str) or "@" not in key:
        return key

    prefix, sep, suffix = key.rpartition("@")
    if not prefix:
        return key

    if is_valid_guid(suffix):
        return prefix

    return key



def normalize_metric_keys(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a dictionary and returns a new dictionary where all keys have machine GUIDs
    stripped using strip_machine_guid. Preserves 'timestamp'.
    """
    if not isinstance(data, dict):
        return data

    normalized: Dict[str, Any] = {}
    guid_keys: Dict[str, Any] = {}
    for k, v in data.items():
        if k == "timestamp":
            normalized["timestamp"] = v
            continue
        if _finite_float(v) is None and isinstance(v, (float, int)):
            continue
        clean_k = strip_machine_guid(str(k))
        if clean_k == str(k):
            normalized[clean_k] = v
        else:
            guid_keys.setdefault(clean_k, v)

    for clean_k, value in guid_keys.items():
        normalized.setdefault(clean_k, value)
    return normalized


def filter_active_metrics(
    data: Dict[str, Any],
    preserve_keys: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """
    Filters out inactive/zero-value entries (None, 0, 0.0) from a metric dictionary,
    but ALWAYS preserves 'timestamp' (and any keys specified in preserve_keys).
    """
    if not isinstance(data, dict):
        return data

    keys_to_preserve = {"timestamp"}
    if preserve_keys:
        keys_to_preserve.update(preserve_keys)

    filtered: Dict[str, Any] = {}
    for k, v in data.items():
        if k in keys_to_preserve:
            filtered[k] = v
            continue
        if v is None:
            continue
        val = _finite_float(v)
        if val is not None:
            if val != 0.0:
                filtered[k] = v
        elif isinstance(v, (int, float)):
            continue
        else:
            if v:
                filtered[k] = v

    return filtered


def extract_top_processes(
    process_data: Any,
    top_n: int = 10,
    sort_by: str = "cpu_pct",
) -> List[Dict[str, Any]]:
    """
    Parses Netdata process metrics (e.g. app.<proc>_cpu_utilization,
    app.<proc>_mem_usage, app.<proc>_fds_open, app.<proc>_threads, with or without @<guid>).
    Extracts process names and groups their metrics.
    Filters out inactive/zero daemons (where both cpu_pct <= 0 and mem_mb <= 0).
    Ranks active processes by CPU and Memory.
    Returns a list of dicts: [{"name": "<proc>", "cpu_pct": <float>, "mem_mb": <float>}, ...].
    Values are rounded cleanly (cpu_pct to 4 decimal places, mem_mb to 2 decimal places).
    """
    if top_n <= 0:
        return []

    if isinstance(process_data, list):
        active = []
        for process in process_data:
            if not isinstance(process, dict):
                continue
            cpu_pct = _process_value(process.get("cpu_pct", 0.0))
            mem_mb = _process_value(process.get("mem_mb", 0.0))
            name = process.get("name")
            if cpu_pct is None or mem_mb is None or not isinstance(name, str) or not name:
                continue
            if cpu_pct <= 0.0 and mem_mb <= 0.0:
                continue
            active.append(
                {
                    "name": name,
                    "cpu_pct": round(cpu_pct, 4),
                    "mem_mb": round(mem_mb, 2),
                }
            )
        sort_mode = str(sort_by or "cpu_pct").lower()
        sort_key = "mem_mb" if "mem" in sort_mode else "cpu_pct"
        sec_key = "cpu_pct" if sort_key == "mem_mb" else "mem_mb"
        active.sort(
            key=lambda p: (-p.get(sort_key, 0.0), -p.get(sec_key, 0.0), p["name"])
        )
        return active[:top_n]

    if not isinstance(process_data, dict):
        return []

    if "top_processes" in process_data and isinstance(process_data["top_processes"], list):
        return extract_top_processes(process_data["top_processes"], top_n=top_n, sort_by=sort_by)

    procs: Dict[str, Dict[str, Any]] = {}

    for raw_k, v in process_data.items():
        if v is None:
            continue

        k = strip_machine_guid(str(raw_k))
        if k == "timestamp":
            continue

        # If already formatted as process dict: e.g. "firefox": {"cpu_pct": ..., "mem_mb": ...}
        if isinstance(v, dict) and ("cpu_pct" in v or "mem_mb" in v):
            cpu_value = _process_value(v.get("cpu_pct", 0.0))
            mem_value = _process_value(v.get("mem_mb", 0.0))
            if cpu_value is None or mem_value is None or not k:
                continue
            cpu = round(cpu_value, 4)
            mem = round(mem_value, 2)
            procs[k] = {"name": k, "cpu_pct": cpu, "mem_mb": mem}
            continue

        clean = k
        if clean.startswith("app."):
            clean = clean[4:]
        elif clean.startswith("apps."):
            clean = clean[5:]

        name = None
        metric = None
        if clean.endswith("_cpu_utilization"):
            name = clean[:-len("_cpu_utilization")]
            metric = "cpu_pct"
        elif clean.endswith("_mem_usage"):
            name = clean[:-len("_mem_usage")]
            metric = "mem_mb"
        elif clean.endswith("_fds_open"):
            name = clean[:-len("_fds_open")]
            metric = "fds_open"
        elif clean.endswith("_threads"):
            name = clean[:-len("_threads")]
            metric = "threads"
        elif clean.endswith("_cpu"):
            name = clean[:-len("_cpu")]
            metric = "cpu_pct"
        elif clean.endswith("_mem"):
            name = clean[:-len("_mem")]
            metric = "mem_mb"

        if name and metric:
            if name not in procs:
                procs[name] = {"name": name, "cpu_pct": 0.0, "mem_mb": 0.0}
            val = _nonnegative_float(v)
            if val is None:
                continue
            if metric == "cpu_pct":
                procs[name]["cpu_pct"] = round(val, 4)
            elif metric == "mem_mb":
                procs[name]["mem_mb"] = round(val, 2)

    # Filter out inactive daemons (both cpu_pct <= 0 and mem_mb <= 0)
    active = [
        p for p in procs.values()
        if (p.get("cpu_pct", 0.0) > 0.0 or p.get("mem_mb", 0.0) > 0.0)
    ]

    # Rank active processes by CPU and Memory
    sort_mode = str(sort_by or "cpu_pct").lower()
    sort_key = "mem_mb" if "mem" in sort_mode else "cpu_pct"
    sec_key = "cpu_pct" if sort_key == "mem_mb" else "mem_mb"
    active.sort(
        key=lambda p: (-p.get(sort_key, 0.0), -p.get(sec_key, 0.0), p["name"])
    )

    return active[:top_n]


def extract_structured_metrics(
    category: str,
    data: Dict[str, Any],
    ram_total_mb: Optional[float] = None,
    top_n: int = 10,
) -> Dict[str, Any]:
    """
    Helper that takes category ('system', 'processes', 'network', 'containers') and the raw or normalized dict, and extracts:
    - cpu_pct: float or None (from system.cpu or process total cpu)
    - ram_used_mb: float or None (from system.ram or used or ram_used_mb)
    - ram_total_mb: float or None (from ram_total_mb or ram sum or parameter)
    - load_avg: float or None (from system.load or load_avg or load_1m)
    - swap_used_mb: float or None (from mem.swap or swap_used_mb)
    - top_processes: list or None (from extract_top_processes if category == 'processes')
    """
    if not isinstance(data, dict):
        resolved_total = _finite_float(ram_total_mb)
        return {
            "cpu_pct": None,
            "ram_used_mb": None,
            "ram_total_mb": round(resolved_total, 2) if resolved_total is not None else None,
            "load_avg": None,
            "swap_used_mb": None,
            "top_processes": None,
        }

    norm = normalize_metric_keys(data)
    category = category.lower() if isinstance(category, str) else ""

    cpu_pct: Optional[float] = None
    ram_used_mb: Optional[float] = None
    load_avg: Optional[float] = None
    swap_used_mb: Optional[float] = None
    top_processes: Optional[List[Dict[str, Any]]] = None

    # Handle top_processes if category == 'processes' or if process metrics are present
    if category == "processes" or any(k.startswith("app.") or k.startswith("apps.") for k in norm.keys()):
        top_procs = extract_top_processes(norm, top_n=top_n)
        if category == "processes" or top_procs:
            top_processes = top_procs
    elif "top_processes" in norm and isinstance(norm["top_processes"], list):
        top_processes = extract_top_processes(norm["top_processes"], top_n=top_n)

    # 1. cpu_pct: from system.cpu, cpu_pct, or process total cpu
    if norm.get("system.cpu") is not None:
        try:
            cpu_pct = round(float(norm["system.cpu"]), 4)
        except (ValueError, TypeError):
            pass
    elif norm.get("cpu_pct") is not None:
        try:
            cpu_pct = round(float(norm["cpu_pct"]), 4)
        except (ValueError, TypeError):
            pass
    elif norm.get("cpu") is not None:
        try:
            cpu_pct = round(float(norm["cpu"]), 4)
        except (ValueError, TypeError):
            pass
    elif norm.get("cgroup.cpu") is not None:
        try:
            cpu_pct = round(float(norm["cgroup.cpu"]), 4)
        except (ValueError, TypeError):
            pass
    elif norm.get("user") is not None:
        try:
            u = float(norm["user"])
            s = float(norm.get("system", 0.0))
            cpu_pct = round(u + s, 4)
        except (ValueError, TypeError):
            pass
    elif category == "processes":
        all_procs = extract_top_processes(norm, top_n=max(len(norm), 1))
        if all_procs:
            cpu_pct = round(sum(p["cpu_pct"] for p in all_procs), 4)

    # 2. ram_used_mb: from system.ram, ram_used_mb, used
    if norm.get("system.ram") is not None:
        try:
            ram_used_mb = round(float(norm["system.ram"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("ram_used_mb") is not None:
        try:
            ram_used_mb = round(float(norm["ram_used_mb"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("used") is not None:
        try:
            ram_used_mb = round(float(norm["used"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("ram_used") is not None:
        try:
            ram_used_mb = round(float(norm["ram_used"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("cgroup.mem_usage") is not None:
        try:
            ram_used_mb = round(float(norm["cgroup.mem_usage"]), 2)
        except (ValueError, TypeError):
            pass
    elif category == "processes":
        all_procs = extract_top_processes(norm, top_n=max(len(norm), 1))
        if all_procs:
            ram_used_mb = round(sum(p["mem_mb"] for p in all_procs), 2)

    # 3. ram_total_mb: from parameter, ram_total_mb, ram_total, or ram sum
    resolved_ram_total_mb: Optional[float] = None
    if ram_total_mb is not None:
        try:
            resolved_ram_total_mb = round(float(ram_total_mb), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("ram_total_mb") is not None:
        try:
            resolved_ram_total_mb = round(float(norm["ram_total_mb"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("ram_total") is not None:
        try:
            val = _finite_float(norm["ram_total"])
            if val is not None:
                if val > 1024 * 1024:
                    val = val / (1024 * 1024)
                resolved_ram_total_mb = round(val, 2)
        except (ValueError, TypeError):
            pass
    elif all(k in norm and norm[k] is not None for k in ("free", "used")):
        try:
            total = sum(
                float(norm[k])
                for k in ("free", "used", "cached", "buffers")
                if k in norm and norm[k] is not None
            )
            resolved_ram_total_mb = round(total, 2)
        except (ValueError, TypeError):
            pass

    # 4. load_avg: from system.load, load_avg, load_1m
    if norm.get("system.load") is not None:
        try:
            load_avg = round(float(norm["system.load"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("load_avg") is not None:
        try:
            load_avg = round(float(norm["load_avg"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("load_1m") is not None:
        try:
            load_avg = round(float(norm["load_1m"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("load") is not None:
        try:
            load_avg = round(float(norm["load"]), 2)
        except (ValueError, TypeError):
            pass

    # 5. swap_used_mb: from mem.swap, swap_used_mb
    if norm.get("mem.swap") is not None:
        try:
            swap_used_mb = round(float(norm["mem.swap"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("swap_used_mb") is not None:
        try:
            swap_used_mb = round(float(norm["swap_used_mb"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("system.swap") is not None:
        try:
            swap_used_mb = round(float(norm["system.swap"]), 2)
        except (ValueError, TypeError):
            pass
    elif norm.get("swap") is not None:
        try:
            swap_used_mb = round(float(norm["swap"]), 2)
        except (ValueError, TypeError):
            pass

    return {
        "cpu_pct": cpu_pct,
        "ram_used_mb": ram_used_mb,
        "ram_total_mb": resolved_ram_total_mb,
        "load_avg": load_avg,
        "swap_used_mb": swap_used_mb,
        "top_processes": top_processes,
    }
