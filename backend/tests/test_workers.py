import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from core.database import get_sync_session, AsyncSessionLocal
from models.node import MonitoredNode
from models.metric import MetricSnapshot
from services.metrics import MetricsService
from workers.maintenance_tasks import prune_old_snapshots


@pytest.fixture
def local_node_sync():
    with get_sync_session() as session:
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == "test-fixture-node")
        node = session.execute(stmt).scalar_one_or_none()
        if not node:
            node = MonitoredNode(
                hostname="test-fixture-node",
                collector_url="http://127.0.0.1:20000",
                os_type="linux",
                active=True,
            )
            session.add(node)
            session.commit()
            session.refresh(node)
        elif not node.active:
            node.active = True
            session.commit()
            session.refresh(node)

    yield node

    try:
        with get_sync_session() as cleanup_session:
            n = cleanup_session.execute(select(MonitoredNode).where(MonitoredNode.id == node.id)).scalar_one_or_none()
            if n:
                cleanup_session.delete(n)
                cleanup_session.commit()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_metrics_service_without_collector(local_node_sync):
    svc = MetricsService()
    with get_sync_session() as session:
        result = await svc.collect_and_persist(local_node_sync.id, session)
        assert result is False


def test_prune_old_snapshots_maintenance(local_node_sync):
    # Insert an old snapshot (>24h) and a fresh snapshot
    old_time = datetime.now(timezone.utc) - timedelta(hours=36)
    fresh_time = datetime.now(timezone.utc) - timedelta(minutes=5)

    with get_sync_session() as session:
        old_snap = MetricSnapshot(
            node_id=local_node_sync.id,
            category="system",
            collected_at=old_time,
            data={"test": "old"},
        )
        fresh_snap = MetricSnapshot(
            node_id=local_node_sync.id,
            category="system",
            collected_at=fresh_time,
            data={"test": "fresh"},
        )
        session.add_all([old_snap, fresh_snap])
        session.commit()
        old_id = old_snap.id
        fresh_id = fresh_snap.id

    # Run maintenance task
    prune_old_snapshots()

    # Verify old snapshot was removed and fresh snapshot retained
    with get_sync_session() as session:
        check_old = session.execute(
            select(MetricSnapshot).where(
                MetricSnapshot.id == old_id,
                MetricSnapshot.collected_at == old_time,
            )
        ).scalar_one_or_none()

        check_fresh = session.execute(
            select(MetricSnapshot).where(
                MetricSnapshot.id == fresh_id,
                MetricSnapshot.collected_at == fresh_time,
            )
        ).scalar_one_or_none()

        assert check_old is None
        assert check_fresh is not None
