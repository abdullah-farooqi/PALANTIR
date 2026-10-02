from integrations.netdata.normalizer import (
    strip_machine_guid,
    normalize_metric_keys,
    filter_active_metrics,
    extract_top_processes,
    extract_structured_metrics,
)


def test_strip_machine_guid():
    guid = "87f56850-57c0-43b7-a6e2-13c37aaaa009"
    assert strip_machine_guid(f"system.cpu@{guid}") == "system.cpu"
    assert strip_machine_guid(f"app.firefox_mem_usage@{guid}") == "app.firefox_mem_usage"
    assert strip_machine_guid(f"net.eth0@{guid}") == "net.eth0"
    assert strip_machine_guid("system.cpu@87F56850-57C0-43B7-A6E2-13C37AAAA009") == "system.cpu"
    assert strip_machine_guid("system.cpu@87f5685057c043b7a6e213c37aaaa009") == "system.cpu"
    assert strip_machine_guid("system.cpu@{87f56850-57c0-43b7-a6e2-13c37aaaa009}") == "system.cpu"
    assert strip_machine_guid("system.cpu") == "system.cpu"
    assert strip_machine_guid("system.cpu@invalid") == "system.cpu@invalid"
    assert strip_machine_guid(123) == 123
    assert strip_machine_guid(None) is None


def test_normalize_metric_keys():
    data = {
        "timestamp": 1790756935,
        "system.cpu@87f56850-57c0-43b7-a6e2-13c37aaaa009": 0.630646,
        "system.ram@87f56850-57c0-43b7-a6e2-13c37aaaa009": 3912.471775,
    }
    normalized = normalize_metric_keys(data)
    assert "system.cpu" in normalized
    assert "system.ram" in normalized
    assert "timestamp" in normalized
    assert normalized["system.cpu"] == 0.630646


def test_normalize_metric_keys_prefers_explicit_key_and_drops_nonfinite_values():
    normalized = normalize_metric_keys(
        {
            "metric": 10.0,
            "metric@87f56850-57c0-43b7-a6e2-13c37aaaa009": 20.0,
            "nan_metric": float("nan"),
            "inf_metric": float("inf"),
        }
    )

    assert normalized["metric"] == 10.0
    assert "nan_metric" not in normalized
    assert "inf_metric" not in normalized


def test_filter_active_metrics():
    data = normalize_metric_keys({
        "timestamp": 1790756935,
        "system.cpu@87f56850-57c0-43b7-a6e2-13c37aaaa009": 0.630646,
        "system.ram@87f56850-57c0-43b7-a6e2-13c37aaaa009": 0,
        "net.eth0@87f56850-57c0-43b7-a6e2-13c37aaaa009": 0.0,
        "app.chrome_cpu_utilization@87f56850-57c0-43b7-a6e2-13c37aaaa009": None,
    })
    filtered = filter_active_metrics(data)
    assert "timestamp" in filtered
    assert "system.cpu" in filtered
    assert "system.ram" not in filtered
    assert "net.eth0" not in filtered
    assert "app.chrome_cpu_utilization" not in filtered

    # Test preserve_keys
    filtered_with_preserve = filter_active_metrics(data, preserve_keys={"system.ram"})
    assert "system.ram" in filtered_with_preserve


def test_extract_top_processes():
    guid = "87f56850-57c0-43b7-a6e2-13c37aaaa009"
    process_data = {
        f"app.chrome_cpu_utilization@{guid}": 12.34,
        f"app.chrome_mem_usage@{guid}": 150.2,
        f"app.firefox_cpu_utilization@{guid}": 8.5,
        f"app.firefox_mem_usage@{guid}": 200.5,
        f"app.spotify_cpu_utilization@{guid}": 0.0,
        f"app.spotify_mem_usage@{guid}": 0.0,
        f"app.vscode_cpu_utilization@{guid}": 5.2,
        f"app.vscode_mem_usage@{guid}": 350.75,
    }

    top_procs = extract_top_processes(process_data, top_n=2, sort_by="cpu_pct")
    assert len(top_procs) == 2
    assert top_procs[0]["name"] == "chrome"
    assert top_procs[0]["cpu_pct"] == 12.34
    assert top_procs[1]["name"] == "firefox"

    top_mem = extract_top_processes(process_data, top_n=1, sort_by="mem_mb")
    assert top_mem[0]["name"] == "vscode"
    assert top_mem[0]["mem_mb"] == 350.75
    assert extract_top_processes(process_data, top_n=0) == []

    structured = extract_top_processes(
        [{"name": "rounded", "cpu_pct": 1.234567, "mem_mb": 2.3456}],
        top_n=1,
    )
    assert structured == [{"name": "rounded", "cpu_pct": 1.2346, "mem_mb": 2.35}]
    assert extract_top_processes(
        [{"name": "cpu-only", "cpu_pct": 2.0, "mem_mb": None}],
        top_n=1,
    ) == [{"name": "cpu-only", "cpu_pct": 2.0, "mem_mb": 0.0}]


def test_extract_top_processes_ignores_invalid_values_and_sorts_ties_deterministically():
    process_data = {
        "app.zeta_cpu_utilization": 5.0,
        "app.zeta_mem_usage": 10.0,
        "app.alpha_cpu_utilization": 5.0,
        "app.alpha_mem_usage": 10.0,
        "app.nan_cpu_utilization": float("nan"),
        "app.nan_mem_usage": 1.0,
        "app.negative_cpu_utilization": -2.0,
        "app.negative_mem_usage": 0.0,
        "app.malformed": {"cpu_pct": "not-a-number"},
    }

    assert extract_top_processes(process_data) == [
        {"name": "alpha", "cpu_pct": 5.0, "mem_mb": 10.0},
        {"name": "zeta", "cpu_pct": 5.0, "mem_mb": 10.0},
        {"name": "nan", "cpu_pct": 0.0, "mem_mb": 1.0},
    ]


def test_extract_structured_metrics_system():
    guid = "87f56850-57c0-43b7-a6e2-13c37aaaa009"
    system_data = {
        f"system.cpu@{guid}": 5.63,
        f"system.load@{guid}": 1.24,
        f"system.ram@{guid}": 4096.5,
        f"mem.swap@{guid}": 1024.0,
        "timestamp": 1790756935,
    }

    result = extract_structured_metrics("system", system_data)
    assert result["cpu_pct"] == 5.63
    assert result["ram_used_mb"] == 4096.5
    assert result["load_avg"] == 1.24
    assert result["swap_used_mb"] == 1024.0
    assert result["top_processes"] is None


def test_extract_structured_metrics_processes():
    guid = "87f56850-57c0-43b7-a6e2-13c37aaaa009"
    process_data = {
        f"app.chrome_cpu_utilization@{guid}": 12.34,
        f"app.chrome_mem_usage@{guid}": 150.2,
        f"app.firefox_cpu_utilization@{guid}": 8.5,
        f"app.firefox_mem_usage@{guid}": 200.5,
    }

    result = extract_structured_metrics("processes", process_data, top_n=2)
    assert result["cpu_pct"] == 20.84
    assert result["ram_used_mb"] == 350.7
    assert len(result["top_processes"]) == 2
    assert result["top_processes"][0]["name"] == "chrome"


def test_extract_structured_metrics_with_ram_total():
    system_data = {
        "free": 8192.0,
        "used": 4096.0,
    }
    result = extract_structured_metrics("system", system_data, ram_total_mb=16384.0)
    assert result["ram_total_mb"] == 16384.0


def test_extract_structured_metrics_converts_byte_ram_metadata():
    result = extract_structured_metrics(
        "system",
        {"ram_total": str(16 * 1024 * 1024 * 1024)},
    )

    assert result["ram_total_mb"] == 16384.0


def test_empty_data_structured_metrics():
    result = extract_structured_metrics("system", {})
    assert all(v is None for v in result.values())
