import asyncio
import hashlib

import pytest

from integrations.agent.pcap_contract import PcapFileManifest
from workers.pcap_tasks import _get_source_manifest, _verify_transfer


def manifest_item(**overrides):
    item = {
        "file_id": "capture_20261112T120000Z_0123456789ab.pcap",
        "filename": "capture_20261112T120000Z_0123456789ab.pcap.gz",
        "size_bytes": 24,
        "original_size_bytes": 32,
        "compression": "gzip",
        "status": "ready",
        "interface": "any",
        "snaplen": 128,
        "packet_count": 1,
        "sha256": hashlib.sha256(b"capture bytes for fixture").hexdigest(),
        "hash_status": "complete",
    }
    item.update(overrides)
    return PcapFileManifest.model_validate(item)


def test_transfer_verification_matches_compression_size_and_digest(tmp_path):
    payload = b"capture bytes for fixture"
    file_path = tmp_path / "transfer.partial"
    file_path.write_bytes(payload)
    item = manifest_item(size_bytes=len(payload))

    assert _verify_transfer(item, "application/gzip", len(payload), file_path) == (
        "gzip",
        ".pcap.gz",
        hashlib.sha256(payload).hexdigest(),
    )


@pytest.mark.parametrize(
    ("content_type", "size_bytes", "payload", "expected_error"),
    [
        ("application/gzip", 100, b"capture bytes for fixture", "size"),
        ("application/zstd", 24, b"capture bytes for fixture", "compression"),
        ("application/gzip", 24, b"tampered capture fixture", "SHA-256"),
        ("application/octet-stream", 24, b"capture bytes for fixture", "unsupported"),
    ],
)
def test_transfer_verification_rejects_mismatched_content(content_type, size_bytes, payload, expected_error, tmp_path):
    file_path = tmp_path / "transfer.partial"
    file_path.write_bytes(payload)
    item = manifest_item(size_bytes=24)

    with pytest.raises(RuntimeError, match=expected_error):
        _verify_transfer(item, content_type, size_bytes, file_path)


def test_transfer_verification_waits_for_finalized_compression_and_hash(tmp_path):
    file_path = tmp_path / "transfer.partial"
    file_path.write_bytes(b"capture bytes for fixture")
    item = manifest_item(status="compressing")
    with pytest.raises(RuntimeError, match="still being compressed"):
        _verify_transfer(item, "application/gzip", 24, file_path)

    item = manifest_item(hash_status="pending", sha256=None)
    with pytest.raises(RuntimeError, match="complete PCAP SHA-256"):
        _verify_transfer(item, "application/gzip", 24, file_path)


def test_source_manifest_requires_the_requested_file():
    class FakeClient:
        async def get_pcap_files(self, snapshot_id=None):
            return {"files": []}

    with pytest.raises(RuntimeError, match="no longer lists"):
        asyncio.run(_get_source_manifest(
            FakeClient(),
            "capture_20261112T120000Z_0123456789ab.pcap",
            "b" * 32,
        ))


def test_source_manifest_adapts_the_legacy_zero_original_size():
    class FakeClient:
        async def get_pcap_files(self, snapshot_id=None):
            return {
                "schema_version": 1,
                "files": [{
                    "file_id": "capture_20261112T120000Z_0123456789ab.pcap",
                    "filename": "capture_20261112T120000Z_0123456789ab.pcap",
                    "size_bytes": 32,
                    "original_size_bytes": 0,
                }],
            }

    item = asyncio.run(_get_source_manifest(
        FakeClient(),
        "capture_20261112T120000Z_0123456789ab.pcap",
        None,
    ))
    assert item.original_size_bytes is None
