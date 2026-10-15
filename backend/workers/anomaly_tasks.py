import asyncio
import logging
from sqlalchemy import select
from workers.celery_app import celery_app
from services.anomaly import AnomalyService
from core.database import get_sync_session
from models.node import MonitoredNode
from services.heartbeats import record_task_finish, record_task_start

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def evaluate_all_nodes(self):
    """Runs every 5min. Evaluates anomaly scores for all active nodes."""
    with get_sync_session() as session:
        record_task_start(session, "anomaly_evaluation")
        failures = 0
        try:
            stmt = select(MonitoredNode).where(MonitoredNode.active == True)
            nodes = session.execute(stmt).scalars().all()
            for node in nodes:
                try:
                    svc = AnomalyService()
                    asyncio.run(svc.evaluate_and_trigger(node.id, session))
                except Exception as exc:
                    failures += 1
                    session.rollback()
                    logger.warning(f"Node {node.id} ({node.hostname}) anomaly eval failed: {exc}")
            record_task_finish(
                session,
                "anomaly_evaluation",
                failed=failures > 0,
                error_code="node_evaluation_failures" if failures else None,
            )
        except Exception:
            session.rollback()
            record_task_finish(session, "anomaly_evaluation", failed=True, error_code="task_failed")
            raise
