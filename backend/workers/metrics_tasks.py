import asyncio
import logging
from sqlalchemy import select
from workers.celery_app import celery_app
from services.metrics import MetricsService
from core.database import get_sync_session
from models.node import MonitoredNode
from services.heartbeats import record_task_finish, record_task_start

logger = logging.getLogger(__name__)

NODE_COLLECTION_TIMEOUT_SECONDS = 55
MAX_CONCURRENT_NODE_COLLECTIONS = 8


async def _collect_one(node_id: int, hostname: str, collector_url: str | None) -> bool:
    """Collect one node with its OWN database session so nodes cannot commit/rollback each other."""
    try:
        with get_sync_session() as node_session:
            svc = MetricsService()
            svc.use_collector(collector_url)
            reached = await asyncio.wait_for(
                svc.collect_and_persist(node_id, node_session),
                timeout=NODE_COLLECTION_TIMEOUT_SECONDS,
            )
            if not reached:
                logger.warning("Node %s (%s): host collector not reachable", node_id, hostname)
            return bool(reached)
    except Exception as exc:
        logger.warning("Node %s (%s) collection failed: %s", node_id, hostname, exc)
        return False


async def _collect_batch(batch: list[tuple[int, str, str | None]]) -> int:
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_NODE_COLLECTIONS)

    async def collect_one(item: tuple[int, str, str | None]):
        async with semaphore:
            return await _collect_one(*item)

    results = await asyncio.gather(*(collect_one(item) for item in batch), return_exceptions=True)
    return sum(1 for result in results if result is not True)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def collect_all_nodes(self):
    """Poll the active fleet once per minute with bounded DB concurrency."""
    with get_sync_session() as session:
        record_task_start(session, "metrics_collection")
        failures = 0
        try:
            stmt = select(MonitoredNode).where(MonitoredNode.active == True).order_by(MonitoredNode.id)
            nodes = session.execute(stmt).scalars().all()
            total_nodes = len(nodes)

            if total_nodes == 0:
                record_task_finish(session, "metrics_collection", failed=False)
                return

            batch = [(node.id, node.hostname, node.collector_url) for node in nodes]
            session.commit()  # release the read transaction before the long-running collection
            failures += asyncio.run(_collect_batch(batch))

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
