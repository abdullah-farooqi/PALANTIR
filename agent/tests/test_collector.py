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
