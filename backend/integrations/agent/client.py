"""HTTP client for the PALANTIR host collector (the only telemetry source)."""

from typing import Any

import httpx

from core.config import settings


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
