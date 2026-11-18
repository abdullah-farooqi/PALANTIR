"""Validated contract for collector PCAP snapshot manifests."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator, model_validator

_FILE_ID = re.compile(r"^capture_\d{8}T\d{6}Z_[0-9a-f]{12}\.pcap\d*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_ID = re.compile(r"^[0-9a-f]{32}$")
_COMPRESSION = {"none": "none", "gz": "gzip", "gzip": "gzip", "zst": "zstd", "zstd": "zstd"}
_SUFFIX = {"none": "", "gzip": ".gz", "zstd": ".zst"}
_CURRENT_FILE_FIELDS = {
    "file_id", "filename", "size_bytes", "original_size_bytes", "compression", "status",
    "interface", "snaplen", "packet_count", "sha256", "hash_status",
}


def _validate_current_file_shape(files: Any) -> None:
    if not isinstance(files, list):
        raise ValueError("version 1.0 PCAP manifest files must be a list")
    for item in files:
        if not isinstance(item, dict) or not _CURRENT_FILE_FIELDS.issubset(item):
            raise ValueError("version 1.0 PCAP file manifest is missing required fields")
        if item["filename"] is None or item["compression"] is None or item["hash_status"] is None:
            raise ValueError("version 1.0 PCAP file manifest has missing required values")


class PcapFileManifest(BaseModel):
    """One collector artifact. Unknown fields are ignored for forward compatibility."""

    model_config = ConfigDict(extra="ignore")

    file_id: StrictStr
    filename: StrictStr | None = None
    size_bytes: StrictInt = Field(ge=1)
    original_size_bytes: StrictInt | None = Field(default=None, ge=1)
    capture_started_at: datetime | None = None
    capture_finished_at: datetime | None = None
    duration_seconds: StrictInt | None = Field(default=None, ge=0)
    compression: StrictStr = "none"
    status: Literal["ready", "compressing"] = "ready"
    interface: StrictStr | None = Field(default=None, min_length=1, max_length=256)
    snaplen: StrictInt | None = Field(default=None, ge=1, le=262144)
    packet_count: StrictInt | None = Field(default=None, ge=0)
    sha256: StrictStr | None = None
    hash_status: Literal["pending", "complete", "unavailable", "queue_full"] = "pending"

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        filename = data.get("filename")
        compression = data.get("compression")
        if compression is None and isinstance(filename, str):
            compression = "gzip" if filename.endswith(".gz") else "zstd" if filename.endswith(".zst") else "none"
        data["compression"] = compression or "none"
        if "hash_status" not in data:
            data["hash_status"] = "complete" if data.get("sha256") else "pending"
        return data

    @field_validator("file_id")
    @classmethod
    def validate_file_id(cls, value: str) -> str:
        if not _FILE_ID.fullmatch(value):
            raise ValueError("invalid collector file ID")
        return value

    @field_validator("compression")
    @classmethod
    def normalize_compression(cls, value: str) -> str:
        try:
            return _COMPRESSION[value]
        except KeyError as exc:
            raise ValueError("unsupported PCAP compression") from exc

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.fullmatch(value):
            raise ValueError("invalid SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_artifact_metadata(self) -> "PcapFileManifest":
        if self.original_size_bytes is not None and self.original_size_bytes < 24:
            raise ValueError("original PCAP size is smaller than its header")
        if self.capture_started_at and self.capture_started_at.utcoffset() is None:
            raise ValueError("capture start time must include a timezone")
        if self.capture_finished_at and self.capture_finished_at.utcoffset() is None:
            raise ValueError("capture finish time must include a timezone")
        if (
            self.capture_started_at
            and self.capture_finished_at
            and self.capture_finished_at < self.capture_started_at
        ):
            raise ValueError("capture finish time precedes capture start time")
        if self.hash_status == "complete" and self.sha256 is None:
            raise ValueError("a completed hash status requires a SHA-256 digest")
        if self.filename is not None:
            if self.filename != PurePath(self.filename).name or "/" in self.filename or "\\" in self.filename:
                raise ValueError("collector filename must be a basename")
            expected = self.file_id + _SUFFIX[self.compression]
            if self.filename != expected:
                raise ValueError("collector filename does not match its file ID and compression")
        return self


class PcapSnapshotManifest(BaseModel):
    """Snapshot-level identity and capture trigger returned by the host agent."""

    model_config = ConfigDict(extra="ignore")

    schema_version: StrictStr | StrictInt
    collector_version: StrictStr | None = None
    snapshot_id: StrictStr
    created_at: datetime | None = None
    expires_at: datetime | None = None
    coverage_seconds: StrictInt | None = Field(default=None, ge=0)
    trigger_type: Literal["manual", "alert", "anomaly"] | None = None
    files: list[PcapFileManifest]

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str | int) -> str | int:
        if isinstance(value, bool) or value not in (1, "1.0"):
            raise ValueError("unsupported PCAP manifest schema version")
        return value

    @field_validator("snapshot_id")
    @classmethod
    def validate_snapshot_id(cls, value: str) -> str:
        if not _SNAPSHOT_ID.fullmatch(value):
            raise ValueError("invalid collector snapshot ID")
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("snapshot time must include a timezone")
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("snapshot expiry must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_manifest(self) -> "PcapSnapshotManifest":
        if self.schema_version == "1.0":
            required = {"collector_version", "created_at", "expires_at", "coverage_seconds", "trigger_type"}
            if not required.issubset(self.model_fields_set):
                raise ValueError("version 1.0 snapshot manifest is missing required fields")
            if any(value is None for value in (
                self.collector_version, self.created_at, self.expires_at,
                self.coverage_seconds, self.trigger_type,
            )):
                raise ValueError("version 1.0 snapshot manifest has missing required values")
            if any(not _CURRENT_FILE_FIELDS.issubset(item.model_fields_set) for item in self.files):
                raise ValueError("version 1.0 PCAP file manifest is missing required fields")
        if self.created_at and self.expires_at and self.expires_at <= self.created_at:
            raise ValueError("snapshot expiry must follow its creation time")
        file_ids = [item.file_id for item in self.files]
        if len(file_ids) != len(set(file_ids)):
            raise ValueError("snapshot contains duplicate collector file IDs")
        return self


def validate_pcap_snapshot(payload: Any, expected_trigger: str) -> PcapSnapshotManifest:
    """Validate a collector manifest, adapting older v1 payloads at the boundary."""
    if isinstance(payload, dict) and payload.get("schema_version") == "1.0":
        _validate_current_file_shape(payload.get("files"))
    if isinstance(payload, dict) and payload.get("schema_version") == 1 and isinstance(payload.get("files"), list):
        # Older collectors used zero as a placeholder when original-size metadata
        # was missing. Preserve that row while exposing the unavailable value as null.
        payload = dict(payload)
        legacy_files = []
        for item in payload["files"]:
            if (
                isinstance(item, dict)
                and isinstance(item.get("original_size_bytes"), int)
                and not isinstance(item.get("original_size_bytes"), bool)
                and item["original_size_bytes"] == 0
            ):
                item = {**item, "original_size_bytes": None}
            legacy_files.append(item)
        payload["files"] = legacy_files
    manifest = PcapSnapshotManifest.model_validate(payload)
    if manifest.trigger_type is not None and manifest.trigger_type != expected_trigger:
        raise ValueError("collector snapshot trigger does not match the request")
    return manifest


def validate_pcap_file_list(payload: Any) -> list[PcapFileManifest]:
    """Validate the collector file-list response, adapting its legacy zero placeholder."""
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
        raise ValueError("invalid PCAP file list")
    schema_version = payload.get("schema_version", 1)
    if isinstance(schema_version, bool) or schema_version not in (1, "1.0"):
        raise ValueError("unsupported PCAP file-list schema version")
    if schema_version == "1.0":
        _validate_current_file_shape(payload["files"])
    legacy = schema_version == 1
    return [validate_pcap_file(item, legacy=legacy) for item in payload["files"]]


def validate_pcap_file(payload: Any, *, legacy: bool = False) -> PcapFileManifest:
    """Validate one file entry, normalizing only the known legacy zero placeholder."""
    if (
        legacy
        and isinstance(payload, dict)
        and isinstance(payload.get("original_size_bytes"), int)
        and not isinstance(payload.get("original_size_bytes"), bool)
        and payload["original_size_bytes"] == 0
    ):
        payload = {**payload, "original_size_bytes": None}
    return PcapFileManifest.model_validate(payload)
