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

    @staticmethod
    def _canonical_route_missing(exc: RuntimeError) -> bool:
        message = str(exc).lower()
        return "http 404" in message or "404 not found" in message

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
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"Host collector request failed (HTTP {exc.response.status_code}): {exc}") from exc
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
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=timeout or self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}{path}", params=params, json=json_body, headers=self._headers()
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"Host collector request failed (HTTP {exc.response.status_code}): {exc}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"Host collector request failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Host collector returned a non-object response")
        return payload

    async def info(self) -> dict[str, Any]:
        return await self._get("/api/v1/info", timeout=min(self.timeout, 8.0))

    async def capabilities(self) -> dict[str, Any]:
        try:
            payload = await self._get("/v1/capabilities")
            features = payload.get("capabilities")
            if isinstance(features, list):
                payload["features"] = features
                payload["capabilities"] = {
                    str(item["name"]): item for item in features
                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                }
            payload["observed_at"] = payload.get("collected_at")
            return payload
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            return await self._get("/api/v1/capabilities")

    async def get_metrics(self, category: str) -> dict[str, Any]:
        canonical = "virtual_machines" if category == "vms" else category
        try:
            envelope = await self._get(f"/v1/snapshot/{canonical}")
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            return await self._get(f"/api/v1/metrics/{category}")
        status = envelope.get("status")
        state = status.get("state", "unavailable") if isinstance(status, dict) else str(status or "unavailable")
        legacy_status = {
            "stale": "partial", "unsupported": "not_configured", "missing_configuration": "not_configured",
        }.get(state, state)
        data = envelope.get("data")
        if isinstance(data, dict) and category == "network" and isinstance(data.get("interfaces"), list):
            interface_rows = data["interfaces"]
            data["interface_rows"] = interface_rows
            data["interfaces"] = {
                str(row.get("name")): {key: value for key, value in row.items() if key != "name"}
                for row in interface_rows if isinstance(row, dict) and row.get("name")
            }
        if isinstance(data, dict) and category == "vms" and isinstance(data.get("virtual_machines"), list):
            data["vms"] = data["virtual_machines"]
        return {
            "category": category,
            "schema_version": envelope.get("schema_version", "1.0"),
            "collector_version": envelope.get("collector_version"),
            "observed_at": envelope.get("collected_at"),
            "collected_at": envelope.get("collected_at"),
            "status": legacy_status,
            "status_detail": status,
            "data": data,
        }

    async def get_cpu_samples(self, since: float = 0.0, limit: int = 900) -> dict[str, Any]:
        """Per-second CPU samples newer than `since` (collector clock), oldest first."""
        return await self._get("/api/v1/samples/cpu", {"since": since, "limit": limit})

    async def get_logs(self, since: float, limit: int = 5000) -> dict[str, Any]:
        try:
            envelope = await self._get("/v1/logs", {"since_cursor": str(since), "limit": limit})
            status = envelope.get("status")
            state = status.get("state", "unavailable") if isinstance(status, dict) else str(status or "unavailable")
            return {**envelope, "status": state, "data": envelope.get("data") or {}}
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            return await self._get("/api/v1/logs", {"since": since, "limit": limit})

    async def get_pcap_status(self) -> dict[str, Any]:
        try:
            payload = await self._get("/v1/pcap/status", timeout=min(self.timeout, 8.0))
            status = payload.get("status")
            return {"schema_version": payload.get("schema_version", "1.0"), **(status if isinstance(status, dict) else {})}
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            return await self._get("/api/v1/capture/status", timeout=min(self.timeout, 8.0))

    async def get_pcap_files(self, snapshot_id: str | None = None) -> dict[str, Any]:
        params = {"snapshot_id": snapshot_id} if snapshot_id else None
        return await self._get("/api/v1/capture/files", params=params)

    async def create_pcap_snapshot(self, trigger_type: str = "manual") -> dict[str, Any]:
        if trigger_type not in {"manual", "alert", "anomaly"}:
            raise ValueError("Invalid PCAP trigger type")
        try:
            return await self._post("/v1/pcap/snapshot", params={"trigger_type": trigger_type}, timeout=min(self.timeout, 30.0))
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
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
        try:
            return await self._post(f"/v1/processes/{pid}/terminate", json_body={"signal": signal_type})
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            return await self._post(f"/api/v1/processes/{pid}/kill", params={"signal_type": signal_type})

    async def stop_container(self, container_id: str, timeout_seconds: int = 10) -> dict[str, Any]:
        return await self._container_action(container_id, "stop", timeout_seconds=timeout_seconds)

    async def start_container(self, container_id: str) -> dict[str, Any]:
        return await self._container_action(container_id, "start")

    async def restart_container(self, container_id: str, timeout_seconds: int = 10) -> dict[str, Any]:
        return await self._container_action(container_id, "restart", timeout_seconds=timeout_seconds)

    async def _container_action(self, container_id: str, action: str, **values: Any) -> dict[str, Any]:
        encoded = quote(container_id, safe="")
        try:
            return await self._post(f"/v1/containers/{encoded}/action", json_body={"action": action, **values})
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            params = {"timeout_seconds": values["timeout_seconds"]} if "timeout_seconds" in values else None
            return await self._post(f"/api/v1/containers/{encoded}/{action}", params=params)

    async def get_container_logs(self, container_id: str, tail: int = 200) -> dict[str, Any]:
        encoded = quote(container_id, safe="")
        try:
            payload = await self._get(f"/v1/containers/{encoded}/logs", {"tail": tail})
            data = payload.get("data")
            return {**payload, **(data if isinstance(data, dict) else {})}
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            return await self._get(f"/api/v1/containers/{encoded}/logs", {"tail": tail})

    async def stop_vm(self, vm_id: str, force: bool = False) -> dict[str, Any]:
        return await self._vm_action(vm_id, "stop", force=force)

    async def start_vm(self, vm_id: str) -> dict[str, Any]:
        return await self._vm_action(vm_id, "start")

    async def restart_vm(self, vm_id: str, force: bool = False) -> dict[str, Any]:
        return await self._vm_action(vm_id, "restart", force=force)

    async def _vm_action(self, vm_id: str, action: str, **values: Any) -> dict[str, Any]:
        encoded = quote(vm_id, safe="")
        try:
            return await self._post(f"/v1/vms/{encoded}/action", json_body={"action": action, **values})
        except RuntimeError as exc:
            if not self._canonical_route_missing(exc):
                raise
            params = {"force": values["force"]} if "force" in values else None
            return await self._post(f"/api/v1/vms/{encoded}/{action}", params=params)


