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
)

celery_app.conf.beat_schedule = {
    "collect-metrics-60s": {
        "task": "workers.metrics_tasks.collect_all_nodes",
        "schedule": 60.0,
    },
    "collect-anomaly-5min": {
        "task": "workers.anomaly_tasks.evaluate_all_nodes",
        "schedule": 300.0,
    },
    "prune-snapshots-daily": {
        "task": "workers.maintenance_tasks.prune_old_snapshots",
        "schedule": crontab(hour=3, minute=0),
    },
}

celery_app.autodiscover_tasks([
    "workers.metrics_tasks",
    "workers.anomaly_tasks",
    "workers.maintenance_tasks",
])
