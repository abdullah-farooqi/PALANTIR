"""HTTP client for the PALANTIR host collector (the only telemetry source)."""

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from core.config import settings

_PCAP_FILE_ID = re.compile(r"^capture_\d{8}T\d{6}Z_[0-9a-f]{12}\.pcap\d*$")


class AgentCollectorClient:
    """Thin async client.  `timeout` applies to every request unless a call overrides it.

    The metrics categories (processes, connections, containers) can legitimately take a few
    seconds on a busy host, so the default is deliberately more generous than a health probe.
    """

    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        if settings.AGENT_AUTH_TOKEN:
            return {"X-PALANTIR-Agent-Token": settings.AGENT_AUTH_TOKEN}
        return {}

    async def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=timeout or self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}{path}", params=params, headers=self._headers()
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"Host collector request failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Host collector returned a non-object response")
        return payload

    async def _post(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=timeout or self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}{path}", params=params, headers=self._headers()
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"Host collector request failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Host collector returned a non-object response")
        return payload

    async def info(self) -> dict[str, Any]:
        return await self._get("/api/v1/info", timeout=min(self.timeout, 8.0))

    async def capabilities(self) -> dict[str, Any]:
        return await self._get("/api/v1/capabilities")

    async def get_metrics(self, category: str) -> dict[str, Any]:
        return await self._get(f"/api/v1/metrics/{category}")

    async def get_cpu_samples(self, since: float = 0.0, limit: int = 900) -> dict[str, Any]:
        """Per-second CPU samples newer than `since` (collector clock), oldest first."""
        return await self._get("/api/v1/samples/cpu", {"since": since, "limit": limit})

    async def get_logs(self, since: float, limit: int = 5000) -> dict[str, Any]:
        return await self._get("/api/v1/logs", {"since": since, "limit": limit})

    async def get_pcap_status(self) -> dict[str, Any]:
        return await self._get("/api/v1/capture/status", timeout=min(self.timeout, 8.0))

    async def get_pcap_files(self, snapshot_id: str | None = None) -> dict[str, Any]:
        params = {"snapshot_id": snapshot_id} if snapshot_id else None
        return await self._get("/api/v1/capture/files", params=params)

    async def create_pcap_snapshot(self) -> dict[str, Any]:
        return await self._post("/api/v1/capture/snapshot", timeout=min(self.timeout, 20.0))

    async def start_pcap_capture(self) -> dict[str, Any]:
        return await self._post("/api/v1/capture/start")

    async def stop_pcap_capture(self) -> dict[str, Any]:
        return await self._post("/api/v1/capture/stop", timeout=max(self.timeout, 30.0))

    async def release_pcap_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{32}", snapshot_id):
            raise ValueError("Invalid PCAP snapshot ID")
        return await self._post(f"/api/v1/capture/snapshots/{snapshot_id}/release")

    async def download_pcap_file(
        self,
        file_id: str,
        destination: Path,
        *,
        max_bytes: int,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Stream one finalized capture to disk without buffering it in memory."""
        if not _PCAP_FILE_ID.fullmatch(file_id):
            raise ValueError("Invalid PCAP file ID")
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        url = f"{self.base_url}/api/v1/capture/files/{quote(file_id, safe='')}/content"
        transfer_timeout = httpx.Timeout(
            connect=5.0,
            read=timeout or settings.PCAP_TRANSFER_TIMEOUT_SECONDS,
            write=30.0,
            pool=5.0,
        )
        total = 0
        content_type = "application/octet-stream"
        try:
            async with httpx.AsyncClient(timeout=transfer_timeout) as client:
                async with client.stream("GET", url, headers=self._headers()) as response:
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", content_type).split(";", 1)[0]
                    declared_size = response.headers.get("content-length")
                    if declared_size and int(declared_size) > max_bytes:
                        raise RuntimeError("PCAP file exceeds the configured upload limit")
                    with destination.open("wb") as stream:
                        async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                            total += len(chunk)
                            if total > max_bytes:
                                raise RuntimeError("PCAP file exceeds the configured upload limit")
                            stream.write(chunk)
        except (httpx.HTTPError, OSError, ValueError, RuntimeError) as exc:
            destination.unlink(missing_ok=True)
            raise RuntimeError(f"PCAP file download failed: {exc}") from exc
        return {"size_bytes": total, "content_type": content_type}

    async def kill_process(self, pid: int, signal_type: str = "SIGTERM") -> dict[str, Any]:
        return await self._post(f"/api/v1/processes/{pid}/kill", params={"signal_type": signal_type})

    async def stop_container(self, container_id: str, timeout_seconds: int = 10) -> dict[str, Any]:
        return await self._post(f"/api/v1/containers/{container_id}/stop", params={"timeout_seconds": timeout_seconds})

    async def start_container(self, container_id: str) -> dict[str, Any]:
        return await self._post(f"/api/v1/containers/{container_id}/start")

    async def restart_container(self, container_id: str, timeout_seconds: int = 10) -> dict[str, Any]:
        return await self._post(f"/api/v1/containers/{container_id}/restart", params={"timeout_seconds": timeout_seconds})

    async def get_container_logs(self, container_id: str, tail: int = 200) -> dict[str, Any]:
        return await self._get(f"/api/v1/containers/{container_id}/logs", {"tail": tail})

    async def stop_vm(self, vm_id: str, force: bool = False) -> dict[str, Any]:
        return await self._post(f"/api/v1/vms/{vm_id}/stop", params={"force": force})

    async def start_vm(self, vm_id: str) -> dict[str, Any]:
        return await self._post(f"/api/v1/vms/{vm_id}/start")

    async def restart_vm(self, vm_id: str, force: bool = False) -> dict[str, Any]:
        return await self._post(f"/api/v1/vms/{vm_id}/restart", params={"force": force})


