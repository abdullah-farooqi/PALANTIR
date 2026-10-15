from celery import Celery
from celery.schedules import crontab
from core.config import settings

celery_app = Celery("palantir", broker=settings.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    imports=(
        "workers.metrics_tasks",
        "workers.anomaly_tasks",
        "workers.maintenance_tasks",
        "workers.health_tasks",
        "workers.investigation_tasks",
    ),
)

celery_app.conf.beat_schedule = {
    "collect-metrics-top-of-minute": {
        "task": "workers.metrics_tasks.collect_all_nodes",
        "schedule": crontab(minute="*"),
    },
    "collect-anomaly-5min": {
        "task": "workers.anomaly_tasks.evaluate_all_nodes",
        "schedule": 300.0,
    },
    "celery-beat-heartbeat-30s": {
        "task": "workers.health_tasks.record_beat_heartbeat",
        "schedule": 30.0,
    },
    "prune-snapshots-daily": {
        "task": "workers.maintenance_tasks.prune_old_snapshots",
        "schedule": crontab(hour=3, minute=0),
    },
}
