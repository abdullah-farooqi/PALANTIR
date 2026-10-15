from core.database import get_sync_session
from services.heartbeats import record_task_finish, record_task_start
from workers.celery_app import celery_app


@celery_app.task(name="workers.health_tasks.record_beat_heartbeat")
def record_beat_heartbeat():
    """Confirms Celery Beat schedules work and a worker can consume it."""
    with get_sync_session() as session:
        record_task_start(session, "celery_beat_dispatch")
        record_task_finish(session, "celery_beat_dispatch")
