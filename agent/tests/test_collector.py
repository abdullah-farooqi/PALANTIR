import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector  # noqa: E402


def test_capabilities_handles_denied_host_namespace(monkeypatch):
    original_exists = Path.exists

    def exists(path: Path) -> bool:
        if path == collector.HOST_PROC / "1/ns/net":
            raise PermissionError("permission denied")
        return original_exists(path)

    monkeypatch.setattr(collector.shutil, "which", lambda _command: "/usr/bin/tool")
    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(collector, "AGENT_TOKEN", "")

    result = collector.capabilities()

    assert result["capabilities"]["firewall"]["status"] == "unavailable"
    assert "inaccessible" in result["capabilities"]["firewall"]["reason"]


def test_cpu_delta_matches_top_style_percentages():
    # 1 s interval on one core: 20 user, 10 system, 70 idle jiffies -> 30 % busy
    previous = (100.0, 0.0, 50.0, 800.0, 10.0, 0.0, 0.0, 0.0)
    current = (120.0, 0.0, 60.0, 870.0, 10.0, 0.0, 0.0, 0.0)
    result = collector._cpu_delta(previous, current)
    assert result["cpu_pct"] == 30.0
    assert result["user"] == 20.0 and result["system"] == 10.0 and result["idle"] == 70.0


def test_cpu_delta_rejects_counter_reset_and_empty_interval():
    base = (100.0,) * 8
    assert collector._cpu_delta(base, base) is None
    assert collector._cpu_delta(base, (50.0,) * 8) is None


def test_iowait_is_not_counted_as_busy():
    previous = (0.0,) * 8
    current = (0.0, 0.0, 0.0, 0.0, 100.0, 0.0, 0.0, 0.0)
    assert collector._cpu_delta(previous, current)["cpu_pct"] == 0.0


def test_canonical_category_envelope_uses_versioned_status_and_aliases(monkeypatch):
    collector._CANONICAL_CACHE.clear()
    monkeypatch.setitem(
        collector.COLLECTORS,
        "vms",
        lambda: collector._status_data({"vms": [{"name": "fixture"}]}, "available"),
    )

    result = collector._canonical_collect("vms")

    assert result["schema_version"] == "1.0"
    assert result["category"] == "virtual_machines"
    assert result["status"]["state"] == "available"
    assert result["status"]["last_success"].endswith("Z")
    assert result["data"]["virtual_machines"][0]["name"] == "fixture"


def test_category_refresh_failure_keeps_last_success_as_stale(monkeypatch):
    collector._CANONICAL_CACHE.clear()
    payloads = iter([
        collector._status_data({"hostname": "host-a"}, "available"),
        collector._status_data({"error": "fixture failure"}, "unavailable"),
    ])
    monkeypatch.setitem(collector.COLLECTORS, "system", lambda: next(payloads))
    first = collector._canonical_collect("system")
    collector._CANONICAL_CACHE["system"]["last_attempt"] -= timedelta(seconds=collector.CATEGORY_REFRESH_SECONDS + 1)

    second = collector._canonical_collect("system")

    assert first["status"]["state"] == "available"
    assert second["status"]["state"] == "stale"
    assert second["data"]["hostname"] == "host-a"


def test_aggregate_snapshot_returns_all_canonical_categories(monkeypatch):
    collector._CANONICAL_CACHE.clear()
    monkeypatch.setattr(collector, "AGENT_TOKEN", "")
    for category in collector.CATEGORIES:
        monkeypatch.setitem(
            collector.COLLECTORS,
            category,
            lambda category=category: collector._status_data({"category_source": category}, "available"),
        )

    result = collector.canonical_snapshot(None)

    assert set(result["categories"]) == set(collector.CANONICAL_CATEGORIES)
    assert result["categories"]["virtual_machines"]["data"]["category_source"] == "vms"


def test_aggregate_snapshot_isolates_one_category_failure(monkeypatch):
    collector._CANONICAL_CACHE.clear()
    monkeypatch.setattr(collector, "AGENT_TOKEN", "")
    for category in collector.CATEGORIES:
        if category == "network":
            monkeypatch.setitem(collector.COLLECTORS, category, lambda: (_ for _ in ()).throw(RuntimeError("fixture failure")))
        else:
            monkeypatch.setitem(
                collector.COLLECTORS,
                category,
                lambda category=category: collector._status_data({"category_source": category}, "available"),
            )

    result = collector.canonical_snapshot(None)

    assert result["categories"]["network"]["status"]["state"] == "unavailable"
    assert result["categories"]["system"]["status"]["state"] == "available"


def test_aggregate_snapshot_uses_one_global_timeout_budget(monkeypatch):
    collector._CANONICAL_CACHE.clear()
    monkeypatch.setattr(collector, "AGENT_TOKEN", "")
    monkeypatch.setattr(collector, "CATEGORY_TIMEOUT_SECONDS", 0.05)

    def slow_collector():
        time.sleep(0.25)
        return collector._status_data({"slow": True}, "available")

    for category in collector.CATEGORIES:
        monkeypatch.setitem(collector.COLLECTORS, category, slow_collector)
    started = time.monotonic()

    result = collector.canonical_snapshot(None)
    elapsed = time.monotonic() - started

    for entry in collector._CANONICAL_CACHE.values():
        future = entry.get("future")
        if future is not None:
            future.result(timeout=1)
    assert elapsed < 0.2
    assert len(result["categories"]) == len(collector.CANONICAL_CATEGORIES)


def test_connections_keep_total_count_when_socket_rows_are_capped(monkeypatch):
    socket_row = "0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 100 0 123"
    monkeypatch.setattr(collector, "_MAX_SOCKETS", 1)
    monkeypatch.setattr(collector, "_host_net_file", lambda name: f"header\n{socket_row}\n{socket_row}" if name == "tcp" else "header\n")
    monkeypatch.setattr(collector, "_socket_inode_owners", lambda _wanted: {})

    result = collector.collect_connections()

    assert result["data"]["count"] == 2
    assert result["data"]["truncated"] is True
    assert len(result["data"]["sockets"]) == 1


def test_canonical_logs_disclose_redaction(monkeypatch):
    monkeypatch.setattr(collector, "AGENT_TOKEN", "")
    monkeypatch.setattr(collector, "collect_logs", lambda _since, _limit, redact=True: {
        "status": "available",
        "data": {"events": [{
            "event_id": "event-1", "timestamp": "2026-11-16T12:00:00+00:00",
            "timestamp_epoch": 1794830400.0, "source": "fixture", "severity": "info",
            "service": "test", "pid": 42, "message": "hello", "fields": {}, "parser": "plain",
        }], "next_since": 1794830400.0},
    })

    result = collector.canonical_logs(
        since_cursor=None, limit=1, service=None, severity=None, contains=None,
        pid=None, source=None, since=None, until=None, x_palantir_agent_token=None,
    )

    assert result["data"]["redaction_applied"] is True
    assert "timestamp_epoch" not in result["data"]["events"][0]


def test_canonical_logs_allow_unredacted_mode_only_when_explicit(monkeypatch):
    seen = {}
    monkeypatch.setattr(collector, "AGENT_TOKEN", "")
    monkeypatch.setattr(collector, "UNREDACTED_LOGS", True)
    monkeypatch.setattr(collector, "collect_logs", lambda _since, _limit, redact=True: (
        seen.update(redact=redact) or {"status": "available", "data": {"events": [], "next_since": 0}}
    ))

    result = collector.canonical_logs(
        since_cursor=None, limit=1, service=None, severity=None, contains=None,
        pid=None, source=None, since=None, until=None, x_palantir_agent_token=None,
    )

    assert seen["redact"] is False
    assert result["data"]["redaction_applied"] is False


def test_action_guard_can_be_disabled_without_weakening_legacy_guard(monkeypatch):
    monkeypatch.setattr(collector, "ACTIONS_ENABLED", False)
    monkeypatch.setattr(collector, "AGENT_TOKEN", "configured")

    with pytest.raises(collector.HTTPException) as error:
        collector._guard_actions("configured")

    assert error.value.status_code == 403
    with pytest.raises(collector.HTTPException) as legacy_action_error:
        collector.start_container("container-a", "configured")
    assert legacy_action_error.value.status_code == 403


def test_file_log_parser_keeps_redaction_default_and_supports_explicit_opt_in():
    raw = '{"message":"password=hunter2","token":"secret-value"}'

    redacted = collector._parse_file_log(raw, "/tmp/app.log", 12, 0)
    unredacted = collector._parse_file_log(raw, "/tmp/app.log", 12, 0, redact=False)

    assert "hunter2" not in redacted["message"]
    assert redacted["fields"]["token"] == "[REDACTED]"
    assert "hunter2" in unredacted["message"]
    assert unredacted["fields"]["token"] == "secret-value"


def test_canonical_http_smoke_returns_all_contract_endpoints(monkeypatch):
    monkeypatch.setattr(collector, "AGENT_TOKEN", "")
    with TestClient(collector.app) as client:
        health = client.get("/v1/health")
        capabilities = client.get("/v1/capabilities")
        snapshot = client.get("/v1/snapshot")
        system = client.get("/v1/snapshot/system")

    assert health.status_code == capabilities.status_code == snapshot.status_code == system.status_code == 200
    assert health.json()["uptime_seconds"] >= 0
    assert isinstance(capabilities.json()["capabilities"], list)
    assert set(snapshot.json()["categories"]) == set(collector.CANONICAL_CATEGORIES)
    for category, envelope in snapshot.json()["categories"].items():
        assert envelope["category"] == category
        assert envelope["schema_version"] == "1.0"
        assert set(envelope["status"]) == {"state", "reason", "source", "last_success", "last_attempt"}
    assert system.json()["category"] == "system"


def test_canonical_action_routes_validate_and_delegate_with_auth(monkeypatch):
    monkeypatch.setattr(collector, "AGENT_TOKEN", "configured-token")
    monkeypatch.setattr(collector, "ACTIONS_ENABLED", True)
    monkeypatch.setattr(collector, "start_container", lambda container_id, token: {"container_id": container_id})

    result = collector.canonical_container_action(
        "container-a", {"action": "start"}, "configured-token", "test-user",
    )

    assert result["success"] is True
    assert result["result"]["container_id"] == "container-a"
    with pytest.raises(collector.HTTPException) as error:
        collector.canonical_vm_action("vm-a", {"action": "stop", "force": "yes"}, "configured-token", None)
    assert error.value.status_code == 400


def test_canonical_pcap_routes_keep_auth_and_trigger_metadata(monkeypatch):
    monkeypatch.setattr(collector, "AGENT_TOKEN", "configured-token")
    monkeypatch.setattr(collector._PCAP_MANAGER, "snapshot", lambda trigger_type="manual": {
        "snapshot_id": "a" * 32, "files": [], "trigger_type": trigger_type,
    })

    result = collector.canonical_capture_snapshot("alert", "configured-token")
    status = collector.canonical_capture_status("configured-token")

    assert result["trigger_type"] == "alert"
    assert result["schema_version"] == "1.0"
    assert status["status"]["dropped_files"] >= 0
    with pytest.raises(collector.HTTPException) as error:
        collector.canonical_capture_status(None)
    assert error.value.status_code == 403


def test_process_termination_checks_identity_before_signaling(monkeypatch):
    monkeypatch.setattr(collector, "AGENT_TOKEN", "configured-token")
    monkeypatch.setattr(collector, "ACTIONS_ENABLED", True)

    class Process:
        def __init__(self, _pid):
            self.signals = []

        def name(self):
            return "fixture-process"

        def create_time(self):
            return 1234.0

        def cmdline(self):
            return ["fixture-process", "--safe"]

        def send_signal(self, value):
            self.signals.append(value)

    process = Process(9000)
    monkeypatch.setattr(collector.psutil, "Process", lambda _pid: process)
    with pytest.raises(collector.HTTPException) as mismatch:
        collector.canonical_terminate_process(
            9000, {"expected_process_name": "different-process"}, "configured-token", None,
        )
    assert mismatch.value.status_code == 409
    assert process.signals == []

    result = collector.canonical_terminate_process(
        9000,
        {"signal": "SIGTERM", "expected_process_name": "fixture-process", "expected_start_time": 1234.0},
        "configured-token",
        None,
    )
    assert result["success"] is True
    assert process.signals == [collector.signal.SIGTERM]
