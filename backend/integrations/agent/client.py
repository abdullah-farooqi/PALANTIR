"""HTTP client for the optional PALANTIR host collector."""

from typing import Any

import httpx

from core.config import settings


class AgentCollectorClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        if settings.AGENT_AUTH_TOKEN:
            return {"X-PALANTIR-Agent-Token": settings.AGENT_AUTH_TOKEN}
        return {}

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
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
        return await self._get("/api/v1/info")

    async def capabilities(self) -> dict[str, Any]:
        return await self._get("/api/v1/capabilities")

    async def get_metrics(self, category: str) -> dict[str, Any]:
        return await self._get(f"/api/v1/metrics/{category}")

    async def get_logs(self, since: float, limit: int = 5000) -> dict[str, Any]:
        return await self._get("/api/v1/logs", {"since": since, "limit": limit})
