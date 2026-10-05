from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_session
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.metric import MetricSnapshot
from models.node import MonitoredNode
from models.service_heartbeat import ServiceHeartbeat

router = APIRouter(prefix="/fleet", tags=["Fleet"])


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _worker_status(row: ServiceHeartbeat | None, now: datetime) -> dict:
    if row is None:
        return {"status": "unknown", "last_started_at": None, "last_completed_at": None, "error_code": None}
    if row.status == "running":
        started = _utc(row.last_started_at) if row.last_started_at else now
        status = "running" if (now - started).total_seconds() <= settings.WORKER_HEARTBEAT_STALE_SECONDS else "stale"
    elif row.last_completed_at is None:
        status = "unknown"
    elif (now - _utc(row.last_completed_at)).total_seconds() > settings.WORKER_HEARTBEAT_STALE_SECONDS:
        status = "stale"
    else:
        status = "healthy" if row.status == "completed" else row.status
    return {
        "status": status,
        "last_started_at": row.last_started_at.isoformat() if row.last_started_at else None,
        "last_completed_at": row.last_completed_at.isoformat() if row.last_completed_at else None,
        "last_success_at": row.last_success_at.isoformat() if row.last_success_at else None,
        "last_duration_ms": row.last_duration_ms,
        "run_count": row.run_count,
        "failure_count": row.failure_count,
        "failure_rate": round(row.failure_count / row.run_count, 4) if row.run_count else None,
        "error_code": row.error_code,
    }


@router.get("/summary")
async def get_fleet_summary(session: AsyncSession = Depends(get_session)):
    now = datetime.now(timezone.utc)
    nodes = (await session.execute(select(MonitoredNode))).scalars().all()
    enabled = [node for node in nodes if node.active]
    reachability = {"reachable": 0, "stale": 0, "unreachable": 0}
    for node in enabled:
        age = max(0, (now - _utc(node.last_seen_at)).total_seconds())
        state = (
            "reachable" if age <= settings.NODE_REACHABLE_SECONDS
            else "stale" if age <= settings.NODE_STALE_SECONDS
            else "unreachable"
        )
        reachability[state] += 1

    latest_metric = await session.execute(select(func.max(MetricSnapshot.collected_at)))
    latest_alerts = (
        select(
            AlertEvent.id.label("event_id"),
            func.row_number().over(
                partition_by=(AlertEvent.node_id, AlertEvent.alert_name, AlertEvent.chart),
                order_by=(AlertEvent.received_at.desc(), AlertEvent.id.desc()),
            ).label("rank"),
        )
        .subquery()
    )
    active_alert_count = await session.execute(
        select(func.count())
        .select_from(AlertEvent)
        .join(latest_alerts, AlertEvent.id == latest_alerts.c.event_id)
        .where(latest_alerts.c.rank == 1, AlertEvent.status.in_(("WARNING", "CRITICAL")))
    )
    latest_metric_at = latest_metric.scalar_one_or_none()
    recent_since = now - timedelta(hours=24)
    anomaly_count = await session.execute(
        select(func.count()).select_from(AnomalyEvent).where(AnomalyEvent.detected_at >= recent_since)
    )
    recent_anomalies = await session.execute(
        select(AnomalyEvent, MonitoredNode.hostname)
        .join(MonitoredNode, MonitoredNode.id == AnomalyEvent.node_id)
        .where(AnomalyEvent.detected_at >= recent_since)
        .order_by(AnomalyEvent.detected_at.desc(), AnomalyEvent.id.desc())
        .limit(5)
    )
    heartbeats = (await session.execute(select(ServiceHeartbeat))).scalars().all()
    heartbeat_by_name = {row.name: row for row in heartbeats}

    return {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "nodes": {
            "total": len(nodes),
            "enabled": len(enabled),
            "disabled": len(nodes) - len(enabled),
            **reachability,
        },
        "latest_metric_at": latest_metric_at.isoformat() if latest_metric_at else None,
        "active_alerts": {"count": active_alert_count.scalar_one()},
        "recent_anomalies": {
            "window_since": recent_since.isoformat(),
            "count": anomaly_count.scalar_one(),
            "latest": [
                {
                    "id": event.id,
                    "node_id": event.node_id,
                    "hostname": hostname,
                    "detected_at": event.detected_at.isoformat(),
                    "max_score": event.max_score,
                    "contexts": event.contexts,
                }
                for event, hostname in recent_anomalies.all()
            ],
        },
        "health": {
            "api": {"status": "healthy"},
            "database": {"status": "healthy"},
            "workers": {
                name: _worker_status(heartbeat_by_name.get(name), now)
                for name in ("metrics_collection", "anomaly_evaluation", "celery_beat_dispatch")
            },
            "worker_semantics": "A task heartbeat confirms pipeline execution and reports node-level failures, not per-category or per-node collection success.",
        },
    }
