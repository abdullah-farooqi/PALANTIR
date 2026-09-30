import httpx
from typing import Any, List, Dict, Optional, Type, TypeVar
from .schemas import (
    NetdataDataResponse,
    NetdataWeightsResponse,
    NetdataInfoResponse,
)
from .exceptions import NetdataUnavailable, NetdataParseError

T = TypeVar("T")


class NetdataClient:
    """
    The only class in PALANTIR that knows Netdata exists.
    All API knowledge lives here.
    If Netdata changes an endpoint, only this file changes.
    """

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def info(self) -> NetdataInfoResponse:
        """
        Connectivity probe. Call before any other method on a new node.
        Also use to check ML warmup: ml-info.min-train-samples = 900.
        Anomaly scores are 0 until that many samples are collected.
        """
        return await self._get("/api/v1/info", NetdataInfoResponse)

    async def get_contexts(self) -> dict:
        """
        Discover what metrics are available on this specific device.
        Call once on node registration — store result in monitored_nodes.
        Count varies per device — never assume it matches another node.
        """
        raw = await self._get("/api/v1/contexts", dict)
        return raw.get("contexts", raw)

    async def get_metrics(
        self,
        contexts: List[str],
        after: int = -60,
        group_by: str = "instance",
    ) -> NetdataDataResponse:
        """
        [VERIFIED] All four params are required for correct behavior.
        See reference documentation for what goes wrong when any is missing.

        contexts: use constants from contexts.py — never raw strings
        after:    seconds relative to now (negative) or Unix timestamp
        group_by: 'instance' gives one row per NIC / process / container
        format:   always json2 — handled by this method, not caller
        """
        return await self._get(
            "/api/v3/data",
            NetdataDataResponse,
            params={
                "contexts": ",".join(contexts),
                "after": after,
                "group_by": group_by,
                "format": "json2",
            },
        )

    async def get_anomaly_scores(
        self,
        contexts: List[str],
        after: int = -300,
    ) -> NetdataWeightsResponse:
        """
        [VERIFIED] method=anomaly-rate is correct.
        method=anomaly-detection silently becomes ks2 correlation.
        Scores are 0 for first 900s on every fresh deployment — correct.
        """
        return await self._get(
            "/api/v3/weights",
            NetdataWeightsResponse,
            params={
                "contexts": ",".join(contexts),
                "after": after,
                "method": "anomaly-rate",
                "format": "json2",
            },
        )

    async def get_alerts(self, all_definitions: bool = False) -> dict:
        """
        [VERIFIED] /api/v1/alerts -> 404. Use /api/v1/alarms.
        Empty alarms{} on healthy device = correct, not broken.
        ?all=1 silently ignored -> 0 definitions. Must be bare ?all.
        httpx rebuilds query string from params dict — {"all": True}
        correctly produces ?all, not ?all=True or ?all=1.
        """
        params = {"all": True} if all_definitions else {}
        return await self._get("/api/v1/alarms", dict, params=params)

    async def health_check(self) -> bool:
        try:
            await self.info()
            return True
        except Exception:
            return False

    async def _get(
        self,
        path: str,
        model: Type[T],
        params: Optional[Dict[str, Any]] = None,
    ) -> T:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.get(
                    f"{self.base_url}{path}",
                    params=params or {},
                )
                r.raise_for_status()
                raw = r.json()
                if model is dict:
                    return raw
                if hasattr(model, "model_validate"):
                    return model.model_validate(raw)
                return model(**raw)
        except httpx.TimeoutException:
            raise NetdataUnavailable(f"Timeout: {self.base_url}{path}")
        except httpx.ConnectError:
            raise NetdataUnavailable(f"Connection refused: {self.base_url}{path}")
        except httpx.RequestError as e:
            raise NetdataUnavailable(f"Network error on {self.base_url}{path}: {e}")
        except httpx.HTTPStatusError as e:
            raise NetdataUnavailable(
                f"HTTP {e.response.status_code}: {path}"
            )
        except Exception as e:
            raise NetdataParseError(f"Parse error on {path}: {e}")
