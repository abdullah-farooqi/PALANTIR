import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from integrations.agent.client import AgentCollectorClient
from models.category_status import CategoryCollectionStatus
from models.log_event import LogEvent
from models.metric import MetricSnapshot
from models.node import MonitoredNode

logger = logging.getLogger(__name__)

SOURCE = "palantir-agent"
KNOWN_CATEGORIES = (
    "system", "storage", "network", "services", "processes",
    "connections", "containers", "vms",
)
# Per-second CPU rows are stored in category "system" next to the once-a-minute full snapshot.
# They carry data["sample"] == CPU_SAMPLE_MARKER and only the total CPU figure.
CPU_SAMPLE_MARKER = "cpu_1s"
CPU_FIRST_BACKFILL_SAMPLES = 120      # how much history to pull the very first time a node is polled
CPU_MAX_SAMPLES_PER_POLL = 900
CAPABILITY_REFRESH_SECONDS = 600      # capability discovery is comparatively expensive on the host
MIB = 1024 * 1024


def _finite(value: Any) -> Optional[float]:
    """float(value) when it is a real, finite number - otherwise None (never a made-up 0)."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _mb(value: Any) -> Optional[float]:
    number = _finite(value)
    return round(number / MIB, 2) if number is not None else None


async def _maybe_await(value):
    """The workers use a synchronous Session, the API an AsyncSession - support both."""
    if hasattr(value, "__await__"):
        return await value
    return value


def system_typed_values(data: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """Typed snapshot columns derived from a collector `system` payload (None = not reported)."""
    memory = data.get("memory") if isinstance(data.get("memory"), dict) else {}
    swap = data.get("swap") if isinstance(data.get("swap"), dict) else {}
    load = data.get("load_average")
    load1 = _finite(load[0]) if isinstance(load, list) and load else None
    swap_total = _finite(swap.get("total_bytes"))
    return {
        "cpu_pct": _finite(data.get("cpu_pct")),
        "ram_used_mb": _mb(memory.get("used_bytes")),
        "ram_total_mb": _mb(memory.get("total_bytes")),
        "load_avg": load1,
        "swap_used_mb": _mb(swap.get("used_bytes")) if swap_total else None,
    }


def top_processes_from_payload(data: Dict[str, Any], limit: int = 25) -> Optional[List[Dict[str, Any]]]:
    rows = data.get("top_by_rss")
    if not isinstance(rows, list):
        return None
    cleaned = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cleaned.append({
            "pid": row.get("pid"),
            "name": row.get("name"),
            "cpu_pct": _finite(row.get("cpu_pct")),          # None until the collector has measured it twice
            "mem_mb": _mb(row.get("rss_bytes")),
        })
    cleaned.sort(key=lambda item: ((item["cpu_pct"] or 0.0), (item["mem_mb"] or 0.0)), reverse=True)
    return cleaned[:limit]


class MetricsService:
    """
    Pull flow - business logic for metric collection.
    The PALANTIR host collector is the only telemetry source.
    """

    def __init__(self, node_url: Optional[str] = None):
        # `node_url` is accepted for backwards compatibility with older callers and ignored.
        self.collector: Optional[AgentCollectorClient] = None
        self.contact_successful = False

    def use_collector(self, collector_url: Optional[str]) -> None:
        self.collector = AgentCollectorClient(collector_url) if collector_url else None

    # ------------------------------------------------------------------ entry point
    async def collect_and_persist(self, node_id: int, session) -> bool:
        """
        Called by Celery beat every 60 seconds.
        Collects every category, writes to metric_snapshots and returns True when the
        collector answered at least one request.  One failing category never fails the rest.
        """
        if self.collector:
            await self._collect_host_agent(node_id, session)
        else:
            for category in KNOWN_CATEGORIES:
                await self._record_category_status(
                    session, node_id, category, SOURCE, "not_configured",
                    error_code="collector_not_configured",
                    error_message="No PALANTIR host collector is configured for this node.",
                )

        node = (await _maybe_await(
            session.execute(select(MonitoredNode).where(MonitoredNode.id == node_id))
        )).scalar_one_or_none()
        if node is not None:
            now = datetime.now(timezone.utc)
            node.last_collection_at = now
            if self.contact_successful:
                node.last_seen_at = now
        try:
            if hasattr(session, "commit"):
                await _maybe_await(session.commit())
        except Exception as exc:
            if hasattr(session, "rollback"):
                await _maybe_await(session.rollback())
            logger.error("Failed to commit snapshots for node %s: %s", node_id, exc)
            raise
        return self.contact_successful

    # ------------------------------------------------------------------ status bookkeeping
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
        result = await _maybe_await(session.execute(
            select(CategoryCollectionStatus).where(
                CategoryCollectionStatus.node_id == node_id,
                CategoryCollectionStatus.category == category,
                CategoryCollectionStatus.source == source,
            )
        ))
        record = result.scalar_one_or_none()
        if record is None:
            record = CategoryCollectionStatus(
                node_id=node_id, category=category, source=source, status=status,
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

    # ------------------------------------------------------------------ per-second CPU
    async def _last_cpu_sample_time(self, node_id: int, session, now: datetime) -> Optional[float]:
        """Collector-clock time of the newest per-second sample we already stored (watermark)."""
        try:
            result = await _maybe_await(session.execute(
                select(MetricSnapshot.data)
                .where(
                    MetricSnapshot.node_id == node_id,
                    MetricSnapshot.category == "system",
                    MetricSnapshot.collected_at >= now - timedelta(minutes=20),
                    MetricSnapshot.data["sample"].as_string() == CPU_SAMPLE_MARKER,
                )
                .order_by(MetricSnapshot.collected_at.desc(), MetricSnapshot.id.desc())
                .limit(1)
            ))
            row = result.scalar_one_or_none()
            inner = row.get("data") if isinstance(row, dict) else None
            return _finite(inner.get("t")) if isinstance(inner, dict) else None
        except Exception as exc:  # a watermark miss only means we re-request a short backfill
            logger.debug("Could not read CPU sample watermark for node %s: %s", node_id, exc)
            return None

    async def _cpu_sample_rows(self, node_id: int, session) -> List[MetricSnapshot]:
        """New one-second CPU samples as snapshot rows, timestamped on THIS server's clock."""
        assert self.collector is not None
        now = datetime.now(timezone.utc)
        last_t = await self._last_cpu_sample_time(node_id, session, now)
        try:
            payload = await self.collector.get_cpu_samples(
                since=last_t or 0.0,
                limit=CPU_MAX_SAMPLES_PER_POLL if last_t else CPU_FIRST_BACKFILL_SAMPLES,
            )
            collector_now = _finite(payload.get("now"))
            if collector_now is None or not isinstance(payload.get("samples"), list):
                return []
            if last_t is not None and collector_now < last_t - 1.0:
                # The collector's clock went backwards (NTP step / restart): start a short backfill again.
                last_t = None
                payload = await self.collector.get_cpu_samples(
                    since=max(0.0, collector_now - CPU_FIRST_BACKFILL_SAMPLES),
                    limit=CPU_FIRST_BACKFILL_SAMPLES,
                )
                if not isinstance(payload.get("samples"), list):
                    return []
        except Exception as exc:  # older collectors have no samples endpoint: per-minute snapshots only
            logger.debug("CPU samples unavailable for node %s: %s", node_id, exc)
            return []

        received = datetime.now(timezone.utc)
        rows: List[MetricSnapshot] = []
        for sample in payload["samples"]:
            if not isinstance(sample, dict):
                continue
            t = _finite(sample.get("t"))
            cpu = _finite(sample.get("cpu_pct"))
            if t is None or cpu is None or not 0.0 <= cpu <= 100.0:
                continue
            if last_t is not None and t <= last_t:
                continue
            # Convert via "age" so a skewed clock on the monitored host cannot put samples in the future.
            stamp = received - timedelta(seconds=max(0.0, collector_now - t))
            rows.append(MetricSnapshot(
                node_id=node_id,
                category="system",
                collected_at=stamp,
                data={
                    "schema_version": 1,
                    "source": SOURCE,
                    "status": "available",
                    "sample": CPU_SAMPLE_MARKER,
                    "observed_at": stamp.isoformat(),
                    "data": {"t": t, "cpu_pct": cpu},
                },
                cpu_pct=cpu,
            ))
        return rows

    # ------------------------------------------------------------------ host collector
    async def _collect_host_agent(self, node_id: int, session) -> None:
        """Collect all host telemetry categories and structured journal/application events."""
        assert self.collector is not None
        # "system" goes first: its CPU figure is a window that ended *before* this poll started to
        # load the host with the heavier process / socket / container scans.
        for category in KNOWN_CATEGORIES:
            attempted_at = datetime.now(timezone.utc)
            try:
                payload = await self.collector.get_metrics(category)
                self.contact_successful = True
                await self._persist_category(node_id, session, category, payload, attempted_at)
                # Save each category as soon as it is collected: a slow later category must never
                # throw away the CPU/memory data already gathered in this poll.
                await _maybe_await(session.commit())
            except Exception as exc:
                if hasattr(session, "rollback"):
                    await _maybe_await(session.rollback())
                await self._record_category_status(
                    session, node_id, category, SOURCE, "collection_error",
                    attempted_at=attempted_at,
                    error_code="collector_request_failed",
                    error_message="The host collector category request failed.",
                )
                logger.info("Host collector %s category unavailable for node %s: %s", category, node_id, exc)

        await self._refresh_capabilities(node_id, session)
        await self._collect_logs(node_id, session)

    async def _persist_category(self, node_id: int, session, category: str, payload: Dict[str, Any],
                                attempted_at: datetime) -> None:
        payload_status = str(payload.get("status", "unavailable"))
        payload_data = payload.get("data")

        if payload_status in {"available", "partial"} and isinstance(payload_data, dict):
            payload["source"] = SOURCE
            typed: Dict[str, Optional[float]] = {}
            top_processes = None
            floor: Optional[datetime] = None

            if category == "system":
                typed = system_typed_values(payload_data)
                # The per-second rows must sort BEFORE the full snapshot, so "newest system snapshot" is always the full one.
                sample_rows = await self._cpu_sample_rows(node_id, session)
                for sample_row in sample_rows:
                    session.add(sample_row)
                if sample_rows:
                    floor = max(row.collected_at for row in sample_rows) + timedelta(milliseconds=1)
                os_release = payload_data.get("os_release")
                if isinstance(os_release, dict):
                    detected = os_release.get("ID") or os_release.get("NAME") or os_release.get("PRETTY_NAME")
                    if detected:
                        node = (await _maybe_await(
                            session.execute(select(MonitoredNode).where(MonitoredNode.id == node_id))
                        )).scalar_one_or_none()
                        if node is not None and node.os_type != str(detected).strip().lower():
                            node.os_type = str(detected).strip().lower()
            elif category == "processes":
                top_processes = top_processes_from_payload(payload_data)

            collected_at = datetime.now(timezone.utc)
            if floor is not None and floor > collected_at:
                collected_at = floor
            session.add(MetricSnapshot(
                node_id=node_id,
                category=category,
                collected_at=collected_at,
                data=payload,
                cpu_pct=typed.get("cpu_pct"),
                ram_used_mb=typed.get("ram_used_mb"),
                ram_total_mb=typed.get("ram_total_mb"),
                load_avg=typed.get("load_avg"),
                swap_used_mb=typed.get("swap_used_mb"),
                top_processes=top_processes,
            ))
            await self._record_category_status(
                session, node_id, category, SOURCE, "available",
                attempted_at=attempted_at, succeeded_at=datetime.now(timezone.utc),
            )
        elif payload_status == "not_configured":
            await self._record_category_status(
                session, node_id, category, SOURCE, "not_configured",
                attempted_at=attempted_at,
                error_code="integration_not_configured",
                error_message="The host collector integration required for this category is not configured.",
            )
        elif payload_status in {"unsupported", "unavailable"}:
            await self._record_category_status(
                session, node_id, category, SOURCE, "unsupported",
                attempted_at=attempted_at,
                error_code="category_unavailable",
                error_message="No supported host source is available for this category.",
            )
        elif payload_status == "permission_denied":
            await self._record_category_status(
                session, node_id, category, SOURCE, "collection_error",
                attempted_at=attempted_at,
                error_code="permission_denied",
                error_message="The host collector lacks permission to read this category.",
            )
        else:
            await self._record_category_status(
                session, node_id, category, SOURCE, "collection_error",
                attempted_at=attempted_at,
                error_code="invalid_collector_response",
                error_message="The host collector returned an invalid category response.",
            )

    async def _refresh_capabilities(self, node_id: int, session) -> None:
        """Capability discovery is expensive on the host, so refresh it every few minutes only."""
        assert self.collector is not None
        try:
            node = (await _maybe_await(
                session.execute(select(MonitoredNode).where(MonitoredNode.id == node_id))
            )).scalar_one_or_none()
            if node is None:
                return
            current = node.capabilities if isinstance(node.capabilities, dict) else None
            observed = None
            if current and isinstance(current.get("observed_at"), str):
                try:
                    observed = datetime.fromisoformat(current["observed_at"].replace("Z", "+00:00"))
                    if observed.tzinfo is None:
                        observed = observed.replace(tzinfo=timezone.utc)
                except ValueError:
                    observed = None
            if observed is not None and (datetime.now(timezone.utc) - observed).total_seconds() < CAPABILITY_REFRESH_SECONDS:
                return
            node.capabilities = await self.collector.capabilities()
            self.contact_successful = True
        except Exception as exc:
            logger.warning("Could not refresh collector capabilities for node %s: %s", node_id, exc)

    async def _collect_logs(self, node_id: int, session) -> None:
        assert self.collector is not None
        try:
            newest = (await _maybe_await(
                session.execute(select(func.max(LogEvent.event_at)).where(LogEvent.node_id == node_id))
            )).scalar()
            if newest is None:
                since = (datetime.now(timezone.utc) - timedelta(seconds=70)).timestamp()
            else:
                if newest.tzinfo is None:
                    newest = newest.replace(tzinfo=timezone.utc)
                # Small overlap protects events sharing a timestamp; event_id makes retries idempotent.
                since = max(0.0, newest.timestamp() - 2.0)
            log_payload = await self.collector.get_logs(since=since)
            events = (log_payload.get("data") or {}).get("events", [])
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
                    await _maybe_await(session.execute(statement))
                except (KeyError, TypeError, ValueError) as exc:
                    logger.debug("Skipping malformed host log event from node %s: %s", node_id, exc)
        except Exception as exc:
            logger.info("Host log collection unavailable for node %s: %s", node_id, exc)
