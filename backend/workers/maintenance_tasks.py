import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import delete
from workers.celery_app import celery_app
from core.database import get_sync_session
from models.metric import MetricSnapshot
from models.log_event import LogEvent
from core.config import settings

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def prune_old_snapshots(self):
    """Prune metric snapshots and structured host logs using configured retention."""
    now = datetime.now(timezone.utc)
    metric_cutoff = now - timedelta(hours=settings.METRICS_RETENTION_HOURS)
    log_cutoff = now - timedelta(days=settings.LOG_RETENTION_DAYS)
    with get_sync_session() as session:
        try:
            result = session.execute(delete(MetricSnapshot).where(MetricSnapshot.collected_at < metric_cutoff))
            log_result = session.execute(delete(LogEvent).where(LogEvent.event_at < log_cutoff))
            session.commit()
            logger.info(
                "Pruned %s metric snapshots and %s log events (metric cutoff %s, log cutoff %s).",
                result.rowcount,
                log_result.rowcount,
                metric_cutoff,
                log_cutoff,
            )
        except Exception as exc:
            logger.error(f"Failed to prune old snapshots: {exc}")
            session.rollback()
