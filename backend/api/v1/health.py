import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from redis import Redis
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.fleet import _worker_status
from core.config import settings
from core.database import get_session
from models.investigation import AgentInvestigation
from models.service_heartbeat import ServiceHeartbeat
from workers.celery_app import celery_app

router = APIRouter(prefix="/health", tags=["Operational health"])


def _redis_probe() -> tuple[bool, int | None]:
    client = Redis.from_url(
        settings.REDIS_URL,
        socket_connect_timeout=0.75,
        socket_timeout=0.75,
        decode_responses=False,
    )
    try:
        client.ping()
        queue_name = celery_app.conf.task_default_queue or "celery"
        queue_depth = 0
        for priority in range(10):
            key = queue_name if priority == 0 else f"{queue_name}\x06\x16{priority}"
            queue_depth += int(client.llen(key))
        return True, queue_depth
    finally:
        client.close()


def _worker_probe() -> list[str]:
    replies = celery_app.control.inspect(timeout=0.75).ping() or {}
    return sorted(replies)


@router.get("/operations")
async def get_operational_health(session: AsyncSession = Depends(get_session)) -> dict:
    now = datetime.now(timezone.utc)
    database = {"status": "healthy"}
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        database = {"status": "unavailable", "error_code": "database_unavailable"}
        try:
            await session.rollback()
        except Exception:
            pass

    try:
        redis_ok, queue_depth = await asyncio.to_thread(_redis_probe)
        redis_health = {"status": "healthy" if redis_ok else "unavailable"}
    except Exception:
        queue_depth = None
        redis_health = {"status": "unavailable", "error_code": "redis_unavailable"}

    try:
        worker_names = await asyncio.to_thread(_worker_probe)
        celery_workers = {"status": "healthy" if worker_names else "unavailable", "workers": worker_names}
    except Exception:
        celery_workers = {"status": "unavailable", "workers": []}

    heartbeat_rows = []
    queued_count = 0
    queue_delays = []
    if database["status"] == "healthy":
        heartbeat_rows = (await session.execute(select(ServiceHeartbeat))).scalars().all()
        since = now - timedelta(hours=24)
        investigations = (await session.execute(
            select(AgentInvestigation.queue_delay_ms)
            .where(
                AgentInvestigation.queued_at >= since,
                AgentInvestigation.queue_delay_ms.is_not(None),
            )
            .order_by(AgentInvestigation.queued_at.desc())
            .limit(500)
        )).scalars().all()
        queue_delays = [int(value) for value in investigations if value is not None]
        queued_count = (await session.execute(
            select(func.count()).select_from(AgentInvestigation).where(AgentInvestigation.status == "queued")
        )).scalar_one()

    heartbeats = {row.name: row for row in heartbeat_rows}
    beat_health = _worker_status(heartbeats.get("celery_beat_dispatch"), now)
    sorted_delays = sorted(queue_delays)
    p95_index = max(0, int(0.95 * (len(sorted_delays) - 1))) if sorted_delays else 0
    dependency_ok = database["status"] == "healthy" and redis_health["status"] == "healthy"
    workers_ok = celery_workers["status"] == "healthy" and beat_health["status"] in {"healthy", "running"}
    return {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "status": "healthy" if dependency_ok and workers_ok else "degraded",
        "api": {"status": "healthy"},
        "database": database,
        "redis": redis_health,
        "celery": {
            "workers": celery_workers,
            "beat_dispatch": beat_health,
            "queue_depth": queue_depth,
            "default_queue": celery_app.conf.task_default_queue or "celery",
        },
        "tasks": {
            name: _worker_status(heartbeats.get(name), now)
            for name in ("metrics_collection", "anomaly_evaluation")
        },
        "investigations": {
            "queued_count": queued_count,
            "queue_delay_window_hours": 24,
            "queue_delay_sample_count": len(sorted_delays),
            "average_queue_delay_ms": round(sum(sorted_delays) / len(sorted_delays), 2) if sorted_delays else None,
            "p95_queue_delay_ms": sorted_delays[p95_index] if sorted_delays else None,
        },
    }
