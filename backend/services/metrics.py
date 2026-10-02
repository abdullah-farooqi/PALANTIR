import logging
import math
from typing import List, Dict, Optional
from integrations.netdata.client import NetdataClient
from integrations.netdata.parsers import parse_rows
from integrations.netdata.contexts import (
    NetworkContexts,
    SystemContexts,
    ProcessContexts,
    ContainerContexts,
)
from integrations.netdata.exceptions import NetdataUnavailable
from models.metric import MetricSnapshot

try:
    from backend.integrations.netdata.normalizer import (
        normalize_metric_keys,
        filter_active_metrics,
        extract_structured_metrics,
    )
except ImportError:
    from integrations.netdata.normalizer import (
        normalize_metric_keys,
        filter_active_metrics,
        extract_structured_metrics,
    )

logger = logging.getLogger(__name__)


class MetricsService:
    """
    Pull flow — business logic for metric collection.
    Nothing above this class knows Netdata exists.
    """

    def __init__(self, node_url: str):
        self.client = NetdataClient(base_url=node_url)
        self._ram_total_mb: Optional[float] = None

    async def get_ram_total_mb(self) -> Optional[float]:
        """
        Queries and caches total RAM from NetdataClient.info() converted from bytes to MB.
        """
        if self._ram_total_mb is not None:
            return self._ram_total_mb
        try:
            info = await self.client.info()
            candidates = [
                getattr(info, "ram_total", None),
                (getattr(info, "host_labels", None) or {}).get("_system_ram_total"),
            ]
            for candidate in candidates:
                if candidate is None:
                    continue
                try:
                    value = float(candidate)
                except (TypeError, ValueError):
                    continue
                if not math.isfinite(value) or value <= 0:
                    continue
                value_mb = value / (1024 * 1024) if value > 1024 * 1024 else value
                self._ram_total_mb = round(value_mb, 2)
                return self._ram_total_mb

            v3_info = await self.client.info_v3()
            if getattr(v3_info, "agents", None):
                agent = v3_info.agents[0]
                value = (
                    agent.get("application", {})
                    .get("hw", {})
                    .get("ram")
                    if isinstance(agent, dict)
                    else None
                )
                if value is not None:
                    try:
                        value = float(value)
                    except (TypeError, ValueError):
                        value = None
                    if value is not None and math.isfinite(value) and value > 0:
                        value_mb = value / (1024 * 1024) if value > 1024 * 1024 else value
                        self._ram_total_mb = round(value_mb, 2)
                        return self._ram_total_mb
        except Exception as e:
            logger.debug(f"Could not retrieve ram_total from node info: {e}")
        return None

    async def collect_network(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                NetworkContexts.BANDWIDTH,
                NetworkContexts.PACKETS,
                NetworkContexts.ERRORS,
                NetworkContexts.DROPS,
            ],
            after=-60,
            group_by="instance",
        )
        return parse_rows(raw)

    async def collect_system(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                SystemContexts.CPU,
                SystemContexts.RAM,
                SystemContexts.SWAP,
                SystemContexts.LOAD,
            ],
            after=-60,
            group_by=None,
        )
        return parse_rows(raw)

    async def collect_processes(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                ProcessContexts.CPU,
                ProcessContexts.MEMORY,
                ProcessContexts.FILES,
                ProcessContexts.THREADS,
            ],
            after=-60,
            group_by="instance",
        )
        return parse_rows(raw)

    async def collect_alerts(self, all_definitions: bool = False) -> Dict:
        return await self.client.get_alerts(all_definitions=all_definitions)

    async def collect_current_alerts(self) -> Dict:
        return await self.client.get_current_alerts()

    async def collect_alert_transitions(self, after: int = -3600, before: Optional[int] = None) -> Dict:
        return await self.client.get_alert_transitions(after=after, before=before)

    async def preflight(self) -> Dict:
        """Return host-derived capability signals before trusting collection."""
        info = await self.client.info()
        contexts = await self.client.get_contexts()
        context_map = contexts.get("contexts", contexts)
        app_contexts = sorted(
            name for name in context_map if name.startswith("app.")
        )
        ml_info = info.ml_info or {}
        return {
            "version": info.version,
            "hostname": (info.host_labels or {}).get("_hostname"),
            "ram_total": info.ram_total or (info.host_labels or {}).get("_system_ram_total"),
            "context_count": len(context_map),
            "app_context_count": len(app_contexts),
            "apps_groups_resolved": bool(app_contexts),
            "ml_enabled": ml_info.get("enabled"),
            "ml_min_training_window": ml_info.get("min-training-window"),
        }

    async def collect_containers(self) -> List[Dict]:
        raw = await self.client.get_metrics(
            contexts=[
                ContainerContexts.CPU,
                ContainerContexts.MEMORY,
            ],
            after=-60,
            group_by="instance",
        )
        return parse_rows(raw)

    async def collect_and_persist(self, node_id: int, session):
        """
        Called by Celery beat every 60 seconds.
        Collects all categories, writes to metric_snapshots.
        If one category fails (node offline or partial error) — logs and continues.
        Does not fail the whole task for one category.
        """
        categories = {
            "network": self.collect_network,
            "system": self.collect_system,
            "processes": self.collect_processes,
            "containers": self.collect_containers,
        }
        ram_total_mb = await self.get_ram_total_mb()

        for category, collector in categories.items():
            try:
                rows = await collector()
                for row in rows:
                    if not isinstance(row, dict):
                        logger.warning(
                            "Skipping malformed %s metric row for node %s",
                            category,
                            node_id,
                        )
                        continue
                    # Clean and normalize keys
                    clean_row = normalize_metric_keys(row)

                    # Filter inactive/zero-value daemons for processes (reducing database bloat)
                    if category == "processes":
                        clean_row = filter_active_metrics(clean_row)

                    # Extract structured metrics: cpu_pct, ram_used_mb, ram_total_mb, load_avg, swap_used_mb, top_processes
                    structured = extract_structured_metrics(
                        category=category,
                        data=clean_row,
                        ram_total_mb=ram_total_mb if category == "system" else None,
                    )

                    # Store in both typed columns and cleaned JSONB data
                    if structured.get("top_processes") is not None:
                        clean_row["top_processes"] = structured["top_processes"]
                    for k in ("cpu_pct", "ram_used_mb", "ram_total_mb", "load_avg", "swap_used_mb"):
                        if structured.get(k) is not None and k not in clean_row:
                            clean_row[k] = structured[k]

                    # Add MetricSnapshot with typed columns to session
                    session.add(
                        MetricSnapshot(
                            node_id=node_id,
                            category=category,
                            data=clean_row,
                            cpu_pct=structured.get("cpu_pct"),
                            ram_used_mb=structured.get("ram_used_mb"),
                            ram_total_mb=structured.get("ram_total_mb"),
                            load_avg=structured.get("load_avg"),
                            swap_used_mb=structured.get("swap_used_mb"),
                            top_processes=structured.get("top_processes"),
                        )
                    )
            except NetdataUnavailable as e:
                logger.warning(
                    f"Node {node_id} offline/unavailable during {category} collection: {e}"
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error collecting {category} for node {node_id}: {e}"
                )
        try:
            if hasattr(session, "commit"):
                res = session.commit()
                if hasattr(res, "__await__"):
                    await res
        except Exception as e:
            if hasattr(session, "rollback"):
                res = session.rollback()
                if hasattr(res, "__await__"):
                    await res
            logger.error(f"Failed to commit snapshots for node {node_id}: {e}")
            raise
