import logging
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.investigation import AgentInvestigation

logger = logging.getLogger(__name__)


async def _maybe_await(value):
    return await value if hasattr(value, "__await__") else value


async def _execute(session, statement):
    return await _maybe_await(session.execute(statement))


def _enqueue(investigation_id: int, job_id: str) -> None:
    # Import locally to avoid a Celery task/service import cycle.
    from workers.investigation_tasks import run_investigation

    run_investigation.apply_async(args=[investigation_id], task_id=job_id)


async def enqueue_investigation_async(
    session,
    *,
    node_id: int,
    trigger_type: str,
    trigger_id: int | None,
) -> tuple[AgentInvestigation, bool]:
    now = datetime.now(timezone.utc)
    job_id = str(uuid4())
    investigation = AgentInvestigation(
        node_id=node_id,
        job_id=job_id,
        queued_at=now,
        trigger_type=trigger_type,
        trigger_id=trigger_id,
        status="queued",
        progress=0,
    )
    session.add(investigation)
    await _maybe_await(session.flush())
    await _maybe_await(session.commit())
    try:
        _enqueue(investigation.id, job_id)
    except Exception:
        await _maybe_await(session.rollback())
        stored = (await _execute(session,
            select(AgentInvestigation).where(AgentInvestigation.id == investigation.id)
        )).scalar_one_or_none()
        if stored is None:
            raise
        stored.status = "failed"
        stored.completed_at = datetime.now(timezone.utc)
        stored.error_code = "dispatch_failed"
        stored.error_message = "The investigation could not be submitted to the worker queue."
        stored.summary = stored.error_message
        await _maybe_await(session.commit())
        return stored, False

    linked = False
    if trigger_type == "alert" and trigger_id is not None:
        event = (await _execute(session, select(AlertEvent).where(
            AlertEvent.id == trigger_id, AlertEvent.node_id == node_id
        ))).scalar_one_or_none()
        if event is not None:
            event.investigation_id = investigation.id
            linked = True
    elif trigger_type == "anomaly" and trigger_id is not None:
        event = (await _execute(session, select(AnomalyEvent).where(
            AnomalyEvent.id == trigger_id, AnomalyEvent.node_id == node_id
        ))).scalar_one_or_none()
        if event is not None:
            event.investigation_id = investigation.id
            linked = True
    try:
        if linked:
            await _maybe_await(session.commit())
        await _maybe_await(session.refresh(investigation))
    except Exception:
        await _maybe_await(session.rollback())
        logger.exception("Investigation %s was queued but its event link could not be saved", investigation.id)
    return investigation, True
