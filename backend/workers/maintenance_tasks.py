import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import delete
from workers.celery_app import celery_app
from core.database import get_sync_session
from models.metric import MetricSnapshot

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def prune_old_snapshots(self):
    """Runs daily. Removes metric snapshots older than 24 hours."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    with get_sync_session() as session:
        try:
            stmt = delete(MetricSnapshot).where(MetricSnapshot.collected_at < cutoff)
            result = session.execute(stmt)
            session.commit()
            logger.info(f"Pruned {result.rowcount} old metric snapshots older than {cutoff}.")
        except Exception as exc:
            logger.error(f"Failed to prune old snapshots: {exc}")
            session.rollback()
