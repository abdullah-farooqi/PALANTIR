import httpx
from typing import Any, Dict, List, Optional, Sequence, Type, TypeVar
from .schemas import (
    NetdataDataResponse,
    NetdataWeightsResponse,
    NetdataInfoResponse,
    NetdataV3InfoResponse,
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

    async def info_v3(self, host: Optional[str] = None) -> NetdataV3InfoResponse:
        """Read v3 agent identity and capabilities from the host endpoint."""
        params = {"host": host} if host else None
        return await self._get("/api/v3/info", NetdataV3InfoResponse, params=params)

    async def get_v3_info(self, host: Optional[str] = None) -> NetdataV3InfoResponse:
        return await self.info_v3(host=host)

    async def get_host_metadata(self) -> Dict[str, Any]:
        """Combine v1 host labels with v3 identity without contacting Cloud."""
        v1_info = await self.info()
        v3_info = await self.info_v3()
        agent = v3_info.agents[0] if v3_info.agents else {}
        labels = v1_info.host_labels or {}
        hardware = agent.get("application", {}).get("hw", {})
        return {
            "hostname": labels.get("_hostname") or agent.get("nm"),
            "machine_guid": agent.get("mg"),
            "node_id": agent.get("nd"),
            "version": v1_info.version or agent.get("application", {}).get("package", {}).get("version"),
            "os": labels.get("_os") or agent.get("application", {}).get("os", {}).get("os"),
            "architecture": labels.get("_architecture") or hardware.get("cpu_architecture"),
            "ram_total": v1_info.ram_total or labels.get("_system_ram_total") or hardware.get("ram"),
            "host_labels": labels,
            "v1": v1_info.model_dump(by_alias=True),
            "v3": v3_info.model_dump(),
        }

    async def get_contexts(self) -> dict:
        """
        Discover what metrics are available on this specific device.
        Call once on node registration — store result in monitored_nodes.
        Count varies per device — never assume it matches another node.
        """
        raw = await self._get("/api/v1/contexts", dict)
        return raw.get("contexts", raw)

    async def get_contexts_v3(self) -> dict:
        return await self._get("/api/v3/contexts", dict)

    async def get_metrics(
        self,
        contexts: Sequence[str],
        after: int = -60,
        group_by: Optional[str] = "instance",
    ) -> NetdataDataResponse:
        """
        [VERIFIED] contexts, after, and json2 are required for correct behavior.
        See reference documentation for what goes wrong when any is missing.

        contexts: use constants from contexts.py — never raw strings
        after:    seconds relative to now (negative) or Unix timestamp
        group_by: 'instance' gives one row per NIC / process / container; None
        leaves Netdata's default aggregation in place for single-instance data.
        format:   always json2 — handled by this method, not caller
        """
        context_names = self._validate_contexts(contexts)
        params: Dict[str, Any] = {
            "contexts": ",".join(context_names),
            "after": after,
            "format": "json2",
        }
        if group_by is not None:
            params["group_by"] = group_by
        return await self._get(
            "/api/v3/data",
            NetdataDataResponse,
            params=params,
        )

    async def get_anomaly_scores(
        self,
        contexts: Sequence[str],
        after: int = -300,
    ) -> NetdataWeightsResponse:
        """
        [VERIFIED] method=anomaly-rate is correct.
        method=anomaly-detection silently becomes ks2 correlation.
        Scores are 0 for first 900s on every fresh deployment — correct.
        """
        context_names = self._validate_contexts(contexts)
        return await self._get(
            "/api/v3/weights",
            NetdataWeightsResponse,
            params={
                "contexts": ",".join(context_names),
                "after": after,
                "method": "anomaly-rate",
            },
        )

    async def get_alerts(self, all_definitions: bool = False) -> dict:
        """
        [VERIFIED] /api/v1/alerts -> 404. Use /api/v1/alarms.
        Empty alarms{} on healthy device = correct, not broken.
        ?all=1 silently ignored -> 0 definitions. Must be the bare ?all flag.
        """
        path = "/api/v1/alarms?all" if all_definitions else "/api/v1/alarms"
        return await self._get(path, dict)

    async def get_current_alerts(
        self,
        options: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Return currently active alert instances from the host's v3 API."""
        selected = (
            list(options)
            if options is not None
            else ["summary", "values", "instances"]
        )
        return await self._post("/api/v3/alerts", {"options": selected})

    async def get_active_alerts(self) -> Dict[str, Any]:
        return await self.get_current_alerts()

    async def get_alert_transitions(
        self,
        after: int = -3600,
        before: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return alert transitions for a host-local time window."""
        payload: Dict[str, Any] = {"after": after}
        if before is not None:
            payload["before"] = before
        return await self._post("/api/v3/alert_transitions", payload)

    async def get_alert_config(self, config: str) -> Dict[str, Any]:
        """Read one alert definition using its v3 configuration hash."""
        if not isinstance(config, str) or not config.strip():
            raise ValueError("config must be a non-empty alert configuration hash")
        return await self._get(
            "/api/v3/alert_config",
            dict,
            params={"config": config.strip()},
        )

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
        return await self._request("GET", path, model, params=params)

    async def _post(
        self,
        path: str,
        payload: Dict[str, Any],
        model: Type[T] = dict,
    ) -> T:
        return await self._request("POST", path, model, json=payload)

    async def _request(
        self,
        method: str,
        path: str,
        model: Type[T],
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> T:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.request(
                    method,
                    f"{self.base_url}{path}",
                    params=params,
                    json=json,
                )
                r.raise_for_status()
                raw = r.json()
                if model is dict:
                    if not isinstance(raw, dict):
                        raise TypeError("expected a JSON object")
                    return raw
                if hasattr(model, "model_validate"):
                    return model.model_validate(raw)
                return model(**raw)
        except httpx.TimeoutException:
            raise NetdataUnavailable(f"Timeout: {self.base_url}{path}")
        except httpx.ConnectError:
            raise NetdataUnavailable(f"Connection refused: {self.base_url}{path}")
        except httpx.HTTPStatusError as e:
            raise NetdataUnavailable(
                f"HTTP {e.response.status_code}: {path}"
            )
        except httpx.RequestError as e:
            raise NetdataUnavailable(f"Network error on {self.base_url}{path}: {e}")
        except Exception as e:
            raise NetdataParseError(f"Parse error on {path}: {e}")

    @staticmethod
    def _validate_contexts(contexts: Sequence[str]) -> List[str]:
        if contexts is None or isinstance(contexts, (str, bytes)):
            raise ValueError("contexts must be a non-empty sequence of names")
        try:
            names = list(contexts)
        except TypeError as exc:
            raise ValueError("contexts must be a non-empty sequence of names") from exc
        if not names or any(
            not isinstance(name, str) or not name.strip() for name in names
        ):
            raise ValueError("contexts must contain at least one non-empty name")
        return [name.strip() for name in names]
