from datetime import datetime, timezone

from sqlalchemy import select

from models.service_heartbeat import ServiceHeartbeat


def record_task_start(session, name: str) -> None:
    now = datetime.now(timezone.utc)
    row = session.execute(
        select(ServiceHeartbeat).where(ServiceHeartbeat.name == name)
    ).scalar_one_or_none()
    if row is None:
        row = ServiceHeartbeat(name=name)
        session.add(row)
    row.last_started_at = now
    row.status = "running"
    row.error_code = None
    session.commit()


def record_task_finish(session, name: str, *, failed: bool = False, error_code: str | None = None) -> None:
    now = datetime.now(timezone.utc)
    row = session.execute(
        select(ServiceHeartbeat).where(ServiceHeartbeat.name == name)
    ).scalar_one_or_none()
    if row is None:
        row = ServiceHeartbeat(name=name, last_started_at=now)
        session.add(row)
    row.last_completed_at = now
    row.status = "failed" if failed else "completed"
    row.error_code = error_code
    row.last_duration_ms = max(
        0,
        int((now - row.last_started_at).total_seconds() * 1000),
    ) if row.last_started_at else None
    row.run_count = (row.run_count or 0) + 1
    if failed:
        row.failure_count = (row.failure_count or 0) + 1
    else:
        row.last_success_at = now
    session.commit()
