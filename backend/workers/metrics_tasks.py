import asyncio
import logging
from sqlalchemy import select
from workers.celery_app import celery_app
from services.metrics import MetricsService
from core.database import get_sync_session
from models.node import MonitoredNode
from services.heartbeats import record_task_finish, record_task_start

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def collect_all_nodes(self):
    """Runs every 60s. One task, iterates over all active nodes."""
    with get_sync_session() as session:
        record_task_start(session, "metrics_collection")
        failures = 0
        try:
            stmt = select(MonitoredNode).where(MonitoredNode.active == True)
            nodes = session.execute(stmt).scalars().all()
            for node in nodes:
                try:
                    svc = MetricsService(node_url=node.netdata_url)
                    svc.use_collector(node.collector_url)
                    asyncio.run(svc.collect_and_persist(node.id, session))
                except Exception as exc:
                    failures += 1
                    session.rollback()
                    logger.warning(f"Node {node.id} ({node.hostname}) collection failed: {exc}")
            record_task_finish(
                session,
                "metrics_collection",
                failed=failures > 0,
                error_code="node_collection_failures" if failures else None,
            )
        except Exception:
            session.rollback()
            record_task_finish(session, "metrics_collection", failed=True, error_code="task_failed")
            raise
