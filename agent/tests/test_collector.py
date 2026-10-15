import sys
from pathlib import Path

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
