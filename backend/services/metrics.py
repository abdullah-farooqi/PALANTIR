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
from models.node import MonitoredNode
from models.log_event import LogEvent
from models.category_status import CategoryCollectionStatus
from integrations.agent.client import AgentCollectorClient
from datetime import datetime, timezone, timedelta
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

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
        self.collector: Optional[AgentCollectorClient] = None
        self._ram_total_mb: Optional[float] = None
        self.contact_successful = False

    def use_collector(self, collector_url: Optional[str]) -> None:
        self.collector = AgentCollectorClient(collector_url) if collector_url else None

    async def get_ram_total_mb(self) -> Optional[float]:
        """
        Queries and caches total RAM from NetdataClient.info() converted from bytes to MB.
        """
        if self._ram_total_mb is not None:
            return self._ram_total_mb
        try:
            info = await self.client.info()
            self.contact_successful = True
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
        known_categories = (
            "system", "storage", "network", "services", "processes",
            "connections", "containers", "vms",
        )
        ram_total_mb = await self.get_ram_total_mb()

        # Netdata currently supplies these four categories in this collector.
        # Record the others explicitly so the API can distinguish unsupported
        # from a missing scrape.
        for category in set(known_categories) - set(categories):
            await self._record_category_status(
                session,
                node_id,
                category,
                "netdata",
                "unsupported",
                error_code="source_not_supported",
                error_message="The current Netdata collection pipeline does not collect this category.",
            )

        for category, collector in categories.items():
            attempted_at = datetime.now(timezone.utc)
            try:
                rows = await collector()
                self.contact_successful = True
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
                    clean_row["source"] = "netdata"

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
                await self._record_category_status(
                    session,
                    node_id,
                    category,
                    "netdata",
                    "available",
                    attempted_at=attempted_at,
                    succeeded_at=datetime.now(timezone.utc),
                )
            except NetdataUnavailable as e:
                await self._record_category_status(
                    session,
                    node_id,
                    category,
                    "netdata",
                    "collection_error",
                    attempted_at=attempted_at,
                    error_code="endpoint_unavailable",
                    error_message="The Netdata endpoint did not return a usable response.",
                )
                logger.warning(
                    f"Node {node_id} offline/unavailable during {category} collection: {e}"
                )
            except Exception as e:
                await self._record_category_status(
                    session,
                    node_id,
                    category,
                    "netdata",
                    "collection_error",
                    attempted_at=attempted_at,
                    error_code="collection_failed",
                    error_message="The Netdata category request failed.",
                )
                logger.error(
                    f"Unexpected error collecting {category} for node {node_id}: {e}"
                    )
        if self.collector:
            await self._collect_host_agent(node_id, session)
        else:
            for category in known_categories:
                await self._record_category_status(
                    session,
                    node_id,
                    category,
                    "palantir-agent",
                    "not_configured",
                    error_code="collector_not_configured",
                    error_message="No PALANTIR host collector is configured for this node.",
                )

        activity_result = session.execute(
            select(MonitoredNode).where(MonitoredNode.id == node_id)
        )
        if hasattr(activity_result, "__await__"):
            activity_result = await activity_result
        node = activity_result.scalar_one_or_none()
        if node is not None:
            now = datetime.now(timezone.utc)
            node.last_collection_at = now
            if self.contact_successful:
                node.last_seen_at = now
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

    async def _record_category_status(
        self,
        session,
        node_id: int,
        category: str,
        source: str,
        status: str,
        attempted_at: Optional[datetime] = None,
        succeeded_at: Optional[datetime] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        result = session.execute(
            select(CategoryCollectionStatus).where(
                CategoryCollectionStatus.node_id == node_id,
                CategoryCollectionStatus.category == category,
                CategoryCollectionStatus.source == source,
            )
        )
        if hasattr(result, "__await__"):
            result = await result
        record = result.scalar_one_or_none()
        if record is None:
            record = CategoryCollectionStatus(
                node_id=node_id,
                category=category,
                source=source,
                status=status,
            )
            session.add(record)
        record.status = status
        if attempted_at is not None:
            record.last_attempt_at = attempted_at
        if succeeded_at is not None:
            record.last_success_at = succeeded_at
            record.error_code = None
            record.error_message = None
        else:
            record.error_code = error_code
            record.error_message = error_message

    async def _collect_host_agent(self, node_id: int, session) -> None:
        """Collect supplemental host telemetry and structured journal events."""
        assert self.collector is not None
        try:
            capability_payload = await self.collector.capabilities()
            self.contact_successful = True
            node_result = session.execute(
                select(MonitoredNode).where(MonitoredNode.id == node_id)
            )
            if hasattr(node_result, "scalars"):
                node = node_result.scalars().one_or_none()
                if node is not None:
                    node.capabilities = capability_payload
        except Exception as exc:
            logger.warning("Could not refresh collector capabilities for node %s: %s", node_id, exc)

        # Netdata remains the primary source for these categories. The host
        # collector adds systemd, kernel, socket and runtime detail alongside it.
        categories = ("system", "storage", "network", "services", "processes", "connections", "containers", "vms")
        for category in categories:
            attempted_at = datetime.now(timezone.utc)
            try:
                payload = await self.collector.get_metrics(category)
                self.contact_successful = True
                payload_status = str(payload.get("status", "unavailable"))
                payload_data = payload.get("data")
                if payload_status in {"available", "partial"} and isinstance(payload_data, dict):
                    payload["source"] = "palantir-agent"
                    session.add(MetricSnapshot(node_id=node_id, category=category, data=payload))
                    await self._record_category_status(
                        session, node_id, category, "palantir-agent", "available",
                        attempted_at=attempted_at,
                        succeeded_at=datetime.now(timezone.utc),
                    )
                elif payload_status == "not_configured":
                    await self._record_category_status(
                        session, node_id, category, "palantir-agent", "not_configured",
                        attempted_at=attempted_at,
                        error_code="integration_not_configured",
                        error_message="The host collector integration required for this category is not configured.",
                    )
                elif payload_status in {"unsupported", "unavailable"}:
                    await self._record_category_status(
                        session, node_id, category, "palantir-agent", "unsupported",
                        attempted_at=attempted_at,
                        error_code="category_unavailable",
                        error_message="No supported host source is available for this category.",
                    )
                elif payload_status == "permission_denied":
                    await self._record_category_status(
                        session, node_id, category, "palantir-agent", "collection_error",
                        attempted_at=attempted_at,
                        error_code="permission_denied",
                        error_message="The host collector lacks permission to read this category.",
                    )
                else:
                    await self._record_category_status(
                        session, node_id, category, "palantir-agent", "collection_error",
                        attempted_at=attempted_at,
                        error_code="invalid_collector_response",
                        error_message="The host collector returned an invalid category response.",
                    )
            except Exception as exc:
                await self._record_category_status(
                    session, node_id, category, "palantir-agent", "collection_error",
                    attempted_at=attempted_at,
                    error_code="collector_request_failed",
                    error_message="The host collector category request failed.",
                )
                logger.info("Host collector %s category unavailable for node %s: %s", category, node_id, exc)

        try:
            newest = session.execute(select(func.max(LogEvent.event_at)).where(LogEvent.node_id == node_id)).scalar()
            if newest is None:
                since = (datetime.now(timezone.utc) - timedelta(seconds=70)).timestamp()
            else:
                if newest.tzinfo is None:
                    newest = newest.replace(tzinfo=timezone.utc)
                # Small overlap protects events sharing a timestamp; event_id makes retries idempotent.
                since = max(0.0, newest.timestamp() - 2.0)
            log_payload = await self.collector.get_logs(since=since)
            events = log_payload.get("data", {}).get("events", [])
            for event in events:
                try:
                    event_at = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
                    if event_at.tzinfo is None:
                        event_at = event_at.replace(tzinfo=timezone.utc)
                    values = {
                        "node_id": node_id,
                        "event_id": str(event["event_id"]),
                        "event_at": event_at,
                        "source": str(event.get("source", "unknown"))[:255],
                        "severity": str(event.get("severity", "unknown"))[:32],
                        "service": str(event["service"])[:255] if event.get("service") is not None else None,
                        "pid": int(event["pid"]) if str(event.get("pid", "")).isdigit() else None,
                        "message": str(event.get("message", ""))[:16_384],
                        "fields": event.get("fields") if isinstance(event.get("fields"), dict) else {},
                        "parser": str(event.get("parser", "unknown"))[:64],
                    }
                    statement = pg_insert(LogEvent).values(**values).on_conflict_do_nothing(
                        constraint="uq_log_events_node_event"
                    )
                    session.execute(statement)
                except (KeyError, TypeError, ValueError) as exc:
                    logger.debug("Skipping malformed host log event from node %s: %s", node_id, exc)
        except Exception as exc:
            logger.info("Host log collection unavailable for node %s: %s", node_id, exc)
