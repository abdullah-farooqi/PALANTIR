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
    """
    Runs at top of every minute (:00s).
    Dynamically groups nodes into time slots based on fleet size:
      - Fleet < 20 nodes: 1 Slot  -> All nodes poll together at top-of-minute (:00s).
      - Fleet 20-59 nodes: 2 Slots -> Group 0 at :00s, Group 1 at :30s.
      - Fleet >= 60 nodes: 4 Slots -> Groups at :00s, :15s, :30s, :45s.
    """
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

            # Determine number of slots
            if total_nodes < 20:
                num_slots = 1
            elif total_nodes < 60:
                num_slots = 2
            else:
                num_slots = 4

            slot_interval = 60 // num_slots

            # Group nodes into slots
            slots = {i: [] for i in range(num_slots)}
            for idx, node in enumerate(nodes):
                slot_idx = idx % num_slots
                slots[slot_idx].append(node)

            # Process Slot 0 immediately at :00s
            async def _collect_batch(node_batch):
                async def _single_node(node_item):
                    try:
                        svc = MetricsService(node_url=node_item.netdata_url)
                        svc.use_collector(node_item.collector_url)
                        await svc.collect_and_persist(node_item.id, session)
                    except Exception as exc:
                        logger.warning(f"Node {node_item.id} ({node_item.hostname}) collection failed: {exc}")

                await asyncio.gather(*[_single_node(n) for n in node_batch], return_exceptions=True)

            asyncio.run(_collect_batch(slots[0]))

            # Process subsequent slots after sleeping for slot_interval seconds
            for slot_idx in range(1, num_slots):
                import time
                time.sleep(slot_interval)
                asyncio.run(_collect_batch(slots[slot_idx]))

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
