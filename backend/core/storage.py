"""Storage backend abstraction for PCAP artifacts and evidence."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from core.config import settings

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract interface for storing and retrieving forensic artifacts."""

    @abstractmethod
    def save_artifact(self, prefix: str, content: bytes, extension: str = "bin") -> tuple[str, str]:
        """Save an artifact byte buffer under a run staging prefix.
        Returns (storage_key, sha256).
        """
        ...

    @abstractmethod
    def read_artifact(self, storage_key: str) -> bytes:
        """Read artifact content bytes by storage key."""
        ...

    def get_artifact(self, storage_key: str) -> bytes:
        """Alias for read_artifact."""
        return self.read_artifact(storage_key)

    @abstractmethod
    def purge_prefix(self, prefix: str) -> int:
        """Remove all artifact files stored under a staging prefix (for rollback).
        Returns number of deleted files.
        """
        ...


class LocalFilesystemBackend(StorageBackend):
    """Local content-addressed artifact store using SHA-256 sharding."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or settings.PCAP_STORAGE_DIR).resolve()

    def save_artifact(self, prefix: str, content: bytes, extension: str = "bin") -> tuple[str, str]:
        digest = hashlib.sha256(content).hexdigest()
        clean_ext = extension.strip(".").lower() or "bin"
        # Content-addressed path: {root}/{prefix}/artifacts/{aa}/{aabb}/{sha256}.{ext}
        clean_prefix = prefix.strip("/")
        relative_path = Path(clean_prefix) / "artifacts" / digest[:2] / digest[:4] / f"{digest}.{clean_ext}"
        destination = (self.root / relative_path).resolve()

        # Prevent directory traversal
        try:
            destination.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Artifact storage path traversal attempt detected") from exc

        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp_partial = destination.with_suffix(destination.suffix + ".partial")

        try:
            temp_partial.write_bytes(content)
            os.replace(temp_partial, destination)
        except Exception:
            temp_partial.unlink(missing_ok=True)
            raise

        return str(relative_path.as_posix()), digest

    def read_artifact(self, storage_key: str) -> bytes:
        target = (self.root / storage_key.strip("/")).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Path traversal attempt in artifact key") from exc

        if not target.is_file():
            raise FileNotFoundError(f"Artifact not found: {storage_key}")
        return target.read_bytes()

    def purge_prefix(self, prefix: str) -> int:
        clean_prefix = prefix.strip("/")
        if not clean_prefix:
            return 0

        target_dir = (self.root / clean_prefix).resolve()
        try:
            target_dir.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Path traversal attempt in purge prefix") from exc

        if not target_dir.exists():
            return 0

        count = sum(1 for p in target_dir.rglob("*") if p.is_file())
        try:
            shutil.rmtree(target_dir, ignore_errors=True)
        except Exception as exc:
            logger.warning("Could not purge storage directory %s: %s", target_dir, exc)
        return count


class MinIOBackend(StorageBackend):
    """S3 / MinIO compatible object storage backend."""

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str = "palantir-pcap",
    ) -> None:
        self.endpoint = endpoint
        self.access_key = access_key
        self.secret_key = secret_key
        self.bucket = bucket
        # Lazy initialization
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from minio import Minio
                self._client = Minio(
                    self.endpoint,
                    access_key=self.access_key,
                    secret_key=self.secret_key,
                    secure=False,
                )
                if not self._client.bucket_exists(self.bucket):
                    self._client.make_bucket(self.bucket)
            except ImportError:
                raise RuntimeError("minio package is required for MinIOBackend")
        return self._client

    def save_artifact(self, prefix: str, content: bytes, extension: str = "bin") -> tuple[str, str]:
        digest = hashlib.sha256(content).hexdigest()
        clean_ext = extension.strip(".").lower() or "bin"
        key = f"{prefix.strip('/')}/artifacts/{digest[:2]}/{digest[:4]}/{digest}.{clean_ext}"
        import io
        client = self._get_client()
        client.put_object(
            self.bucket,
            key,
            io.BytesIO(content),
            length=len(content),
        )
        return key, digest

    def read_artifact(self, storage_key: str) -> bytes:
        client = self._get_client()
        response = client.get_object(self.bucket, storage_key.strip("/"))
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def purge_prefix(self, prefix: str) -> int:
        client = self._get_client()
        clean_prefix = prefix.strip("/")
        objects = client.list_objects(self.bucket, prefix=clean_prefix, recursive=True)
        count = 0
        from minio.deleteobjects import DeleteObject
        delete_list = []
        for obj in objects:
            delete_list.append(DeleteObject(obj.object_name))
            count += 1
        if delete_list:
            for del_err in client.remove_objects(self.bucket, delete_list):
                logger.warning("Error deleting minio object: %s", del_err)
        return count


def get_storage_backend() -> StorageBackend:
    """Factory creating the configured storage backend."""
    backend_type = getattr(settings, "PCAP_STORAGE_BACKEND", "local")
    if backend_type == "minio" and getattr(settings, "MINIO_ENDPOINT", None):
        return MinIOBackend(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=getattr(settings, "MINIO_ACCESS_KEY", ""),
            secret_key=getattr(settings, "MINIO_SECRET_KEY", ""),
            bucket=getattr(settings, "MINIO_BUCKET", "palantir-pcap"),
        )
    return LocalFilesystemBackend(root=settings.PCAP_STORAGE_DIR)
