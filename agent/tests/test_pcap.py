import gzip
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pcap import PCapManager, build_bpf_filter


def manager_for(path: Path, **overrides) -> PCapManager:
    config = {
        "enabled": False,
        "interface": "any",
        "snaplen": 128,
        "rotation_seconds": 300,
        "max_files": 3,
        "max_size_mb": 50,
        "filter_exclude": "port 20000 or port 8000",
        "storage_dir": path,
        "compression": "none",
    }
    config.update(overrides)
    return PCapManager(**config)


def test_bpf_filter_excludes_configured_expression_without_ssh_default():
    assert build_bpf_filter("port 20000 or port 8000") == "not (port 20000 or port 8000)"
    assert build_bpf_filter("") == ""


@pytest.mark.parametrize(
    ("field", "value"),
    [("snaplen", 32), ("rotation_seconds", 1), ("max_files", 0), ("max_size_mb", 0), ("compression", "zip")],
)
def test_invalid_capture_configuration_is_rejected(tmp_path, field, value):
    with pytest.raises(ValueError):
        manager_for(tmp_path, **{field: value})


def test_finalized_capture_is_listed_and_resolved_by_opaque_file_id(tmp_path):
    manager = manager_for(tmp_path)
    started_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    filename = "capture_20261112T120000Z_0123456789ab.pcap"
    capture = tmp_path / filename
    capture.write_bytes(b"pcap fixture packet data plus bytes")

    manager._register_closed_files(capture, started_at)

    files = manager.files()
    assert len(files) == 1
    assert files[0]["file_id"] == filename
    assert files[0]["status"] == "ready"
    path, media_type = manager.file_path(filename)
    assert path == capture
    assert media_type == "application/vnd.tcpdump.pcap"


@pytest.mark.parametrize("file_id", ["../secret.pcap", "/tmp/capture.pcap", "capture_bad.pcap"])
def test_file_lookup_rejects_untrusted_paths(tmp_path, file_id):
    manager = manager_for(tmp_path)
    with pytest.raises(FileNotFoundError):
        manager.file_path(file_id)


def test_active_or_unfinalized_capture_cannot_be_downloaded(tmp_path):
    manager = manager_for(tmp_path)
    filename = "capture_20261112T120000Z_0123456789ab.pcap"
    (tmp_path / filename).write_bytes(b"still writing")
    with pytest.raises(FileNotFoundError, match="not finalized"):
        manager.file_path(filename)


def test_unknown_snapshot_does_not_return_the_entire_file_list(tmp_path):
    manager = manager_for(tmp_path)
    assert manager.files("f" * 32) == []


def test_snapshot_pin_survives_manager_restart_and_can_be_released(tmp_path):
    manager = manager_for(tmp_path)
    filename = "capture_20261112T120000Z_0123456789ab.pcap"
    capture = tmp_path / filename
    capture.write_bytes(b"pcap fixture packet data plus bytes")
    manager._register_closed_files(capture, datetime.now(timezone.utc) - timedelta(minutes=1))
    snapshot_id = "a" * 32
    manager._pin(snapshot_id, [filename], datetime.now(timezone.utc) + timedelta(minutes=5))

    restarted = manager_for(tmp_path)
    assert restarted.files(snapshot_id)[0]["file_id"] == filename
    assert restarted.release_snapshot(snapshot_id)
    assert restarted.files(snapshot_id) == []


def test_active_snapshot_count_is_bounded(tmp_path):
    manager = manager_for(tmp_path, max_active_snapshots=1)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert manager._pin("a" * 32, [], expires_at)
    assert not manager._pin("b" * 32, [], expires_at)


def test_gzip_compression_keeps_the_original_capture_as_a_downloadable_artifact(tmp_path):
    manager = manager_for(tmp_path, compression="gzip")
    filename = "capture_20261112T120000Z_0123456789ab.pcap"
    capture = tmp_path / filename
    payload = b"pcap fixture bytes" * 16
    capture.write_bytes(payload)
    manager._register_closed_files(capture, datetime.now(timezone.utc) - timedelta(minutes=1))
    manager._compress_one(capture)

    path, media_type = manager.file_path(filename)
    assert media_type == "application/gzip"
    with gzip.open(path, "rb") as stream:
        assert stream.read() == payload


def test_compressing_files_advertise_the_pending_compression_format(tmp_path):
    manager = manager_for(tmp_path, compression="zstd")
    filename = "capture_20261112T120000Z_0123456789ab.pcap000"
    capture = tmp_path / filename
    capture.write_bytes(b"pcap fixture packet data plus bytes")
    manager._register_closed_files(capture.with_name(capture.name.removesuffix("000")), datetime.now(timezone.utc))
    manager._compressing.add(filename)

    item = manager.files()[0]
    assert item["filename"] == f"{filename}.zst"
    assert item["compression"] == "zstd"
    assert item["status"] == "compressing"


def test_finalized_compression_is_detected_after_configuration_changes(tmp_path):
    manager = manager_for(tmp_path, compression="gzip")
    filename = "capture_20261112T120000Z_0123456789ab.pcap"
    capture = tmp_path / filename
    capture.write_bytes(b"pcap fixture packet data plus bytes")
    manager._register_closed_files(capture, datetime.now(timezone.utc))
    manager._compress_one(capture)

    restarted = manager_for(tmp_path, compression="none")
    item = restarted.files()[0]
    assert item["compression"] == "gz"
    assert item["filename"].endswith(".gz")
    assert restarted.file_path(filename)[0].suffix == ".gz"


def test_packet_timestamps_are_read_from_rotated_pcap_files(tmp_path):
    manager = manager_for(tmp_path)
    filename = "capture_20261112T120000Z_0123456789ab.pcap000"
    capture = tmp_path / filename
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 128, 1)
    packet_header = struct.Struct("<IIII")
    packets = (
        packet_header.pack(1_700_000_000, 100_000, 32, 32) + b"a" * 32
        + packet_header.pack(1_700_000_002, 900_000, 24, 24) + b"b" * 24
    )
    capture.write_bytes(global_header + packets)

    manager._register_closed_files(capture.with_name(capture.name.removesuffix("000")), datetime.now(timezone.utc))

    item = manager.files()[0]
    assert item["capture_started_at"] == "2023-11-14T22:13:20.100000+00:00"
    assert item["capture_finished_at"] == "2023-11-14T22:13:22.900000+00:00"
    assert item["duration_seconds"] == 2

