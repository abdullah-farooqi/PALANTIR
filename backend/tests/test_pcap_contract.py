import pytest
from pydantic import ValidationError

from integrations.agent.pcap_contract import validate_pcap_file_list, validate_pcap_snapshot


def valid_snapshot(**file_overrides):
    file_item = {
        "file_id": "capture_20261112T120000Z_0123456789ab.pcap",
        "filename": "capture_20261112T120000Z_0123456789ab.pcap.zst",
        "size_bytes": 512,
        "original_size_bytes": 4096,
        "capture_started_at": "2026-11-12T12:00:00Z",
        "capture_finished_at": "2026-11-12T12:00:10Z",
        "duration_seconds": 10,
        "compression": "zstd",
        "status": "ready",
        "interface": "any",
        "snaplen": 2048,
        "packet_count": 12,
        "sha256": "a" * 64,
        "hash_status": "complete",
    }
    file_item.update(file_overrides)
    return {
        "schema_version": "1.0",
        "collector_version": "test",
        "snapshot_id": "b" * 32,
        "created_at": "2026-11-12T12:00:11Z",
        "expires_at": "2026-11-12T12:30:11Z",
        "coverage_seconds": 300,
        "trigger_type": "manual",
        "files": [file_item],
    }


def test_manifest_preserves_capture_metadata_and_compression():
    manifest = validate_pcap_snapshot(valid_snapshot(), "manual")
    item = manifest.files[0]

    assert manifest.snapshot_id == "b" * 32
    assert manifest.trigger_type == "manual"
    assert item.file_id == "capture_20261112T120000Z_0123456789ab.pcap"
    assert item.compression == "zstd"
    assert item.original_size_bytes == 4096
    assert item.sha256 == "a" * 64
    assert item.packet_count == 12


@pytest.mark.parametrize(
    "overrides",
    [
        {"file_id": "../capture.pcap"},
        {"filename": "../../capture.pcap.zst"},
        {"filename": "capture_20261112T120000Z_0123456789ab.pcap.gz"},
        {"size_bytes": -1},
        {"size_bytes": True},
        {"snaplen": 300000},
        {"sha256": "not-a-digest"},
        {"sha256": None, "hash_status": "complete"},
        {"capture_finished_at": "2026-11-12T11:59:00Z"},
        {"compression": "zip"},
    ],
)
def test_manifest_rejects_invalid_artifact_metadata(overrides):
    with pytest.raises(ValidationError):
        validate_pcap_snapshot(valid_snapshot(**overrides), "manual")


def test_manifest_rejects_trigger_mismatch_and_duplicate_file_ids():
    payload = valid_snapshot()
    payload["trigger_type"] = "alert"
    with pytest.raises(ValueError, match="trigger"):
        validate_pcap_snapshot(payload, "manual")

    payload = valid_snapshot()
    payload["files"].append(dict(payload["files"][0]))
    with pytest.raises(ValidationError, match="duplicate"):
        validate_pcap_snapshot(payload, "manual")


def test_current_manifest_rejects_missing_contract_fields():
    payload = valid_snapshot()
    del payload["files"][0]["compression"]
    with pytest.raises(ValueError, match="missing required fields"):
        validate_pcap_snapshot(payload, "manual")

    payload = valid_snapshot()
    payload["collector_version"] = None
    with pytest.raises(ValidationError, match="missing required values"):
        validate_pcap_snapshot(payload, "manual")


def test_legacy_manifest_gets_explicit_optional_metadata_without_fabrication():
    payload = valid_snapshot()
    payload["schema_version"] = 1
    payload.pop("trigger_type")
    payload["files"][0].pop("interface")
    payload["files"][0].pop("snaplen")
    payload["files"][0].pop("packet_count")
    payload["files"][0].pop("sha256")
    payload["files"][0].pop("hash_status")
    payload["files"][0]["original_size_bytes"] = 0

    item = validate_pcap_snapshot(payload, "manual").files[0]
    assert item.interface is None
    assert item.snaplen is None
    assert item.packet_count is None
    assert item.original_size_bytes is None
    assert item.sha256 is None
    assert item.hash_status == "pending"


def test_legacy_file_list_normalizes_the_old_zero_size_placeholder():
    payload = {"schema_version": 1, "files": [{
        "file_id": "capture_20261112T120000Z_0123456789ab.pcap",
        "filename": "capture_20261112T120000Z_0123456789ab.pcap",
        "size_bytes": 512,
        "original_size_bytes": 0,
    }]}

    assert validate_pcap_file_list(payload)[0].original_size_bytes is None

    payload["files"][0]["filename"] = "../../capture.pcap"
    with pytest.raises(ValidationError):
        validate_pcap_file_list(payload)
