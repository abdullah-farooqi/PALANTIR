from core.config import settings

try:
    from celery import Celery
    from celery.schedules import crontab
    celery_app = Celery("palantir", broker=settings.REDIS_URL)
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    crontab = lambda **kwargs: kwargs

    class _DummyConf:
        def __init__(self):
            self.beat_schedule = {}

        def update(self, *args, **kwargs):
            pass

    class _DummyCelery:
        def __init__(self):
            self.conf = _DummyConf()

        def task(self, *args, **kwargs):
            def decorator(fn):
                fn.delay = fn
                fn.apply_async = lambda *a, **k: fn(*a, **k)
                fn.s = lambda *a, **k: fn
                fn.si = lambda *a, **k: fn
                return fn
            return decorator

    celery_app = _DummyCelery()

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
        "workers.pcap_tasks",
        "workers.pcap_pipeline",
    ),
    task_routes={
        "workers.pcap_pipeline.*": {"queue": "pcap_analysis"},
        "workers.pcap_tasks.*": {"queue": "pcap_transfer"},
        "workers.metrics_tasks.*": {"queue": "default"},
        "workers.anomaly_tasks.*": {"queue": "default"},
        "workers.maintenance_tasks.*": {"queue": "default"},
        "workers.health_tasks.*": {"queue": "default"},
        "workers.investigation_tasks.*": {"queue": "default"},
    },
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=settings.PCAP_TASK_SOFT_TIME_LIMIT,
    task_time_limit=settings.PCAP_TASK_TIME_LIMIT,
    worker_max_tasks_per_child=settings.PCAP_MAX_TASKS_PER_CHILD,
)

celery_app.conf.beat_schedule = {
    "collect-metrics-top-of-minute": {
        "task": "workers.metrics_tasks.collect_all_nodes",
        "schedule": crontab(minute="*"),
        # A delayed full-fleet poll is obsolete once the next minute's poll is due.
        "options": {"expires": 55},
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
