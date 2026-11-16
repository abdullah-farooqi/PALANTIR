import asyncio
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from core.database import get_sync_session, AsyncSessionLocal
from models.node import MonitoredNode
from models.metric import MetricSnapshot
from services.metrics import MetricsService
from workers import metrics_tasks
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


@pytest.mark.asyncio
async def test_system_snapshot_keeps_distro_in_json_without_changing_os_family(monkeypatch):
    service = MetricsService()

    class FakeSession:
        def __init__(self):
            self.added = []

        def add(self, row):
            self.added.append(row)

        async def execute(self, _statement):
            raise AssertionError("system snapshot persistence should not rewrite the node OS family")

    session = FakeSession()

    async def no_cpu_samples(_node_id, _session):
        return []

    async def no_alerts(_node_id, _session, _typed):
        return None

    async def no_status(*_args, **_kwargs):
        return None

    monkeypatch.setattr(service, "_cpu_sample_rows", no_cpu_samples)
    monkeypatch.setattr(service, "_evaluate_system_alerts", no_alerts)
    monkeypatch.setattr(service, "_record_category_status", no_status)

    await service._persist_category(
        1,
        session,
        "system",
        {"status": "available", "data": {"os_release": {"ID": "ubuntu"}}},
        datetime.now(timezone.utc),
    )

    snapshots = [row for row in session.added if isinstance(row, MetricSnapshot)]
    assert snapshots[0].data["data"]["os_release"]["ID"] == "ubuntu"


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


@pytest.mark.asyncio
async def test_collect_batch_limits_parallel_node_sessions(monkeypatch):
    current = 0
    peak = 0

    async def fake_collect_one(*_item):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.01)
        current -= 1
        return True

    monkeypatch.setattr(metrics_tasks, "_collect_one", fake_collect_one)
    failures = await metrics_tasks._collect_batch(
        [(node_id, f"node-{node_id}", None) for node_id in range(25)]
    )

    assert failures == 0
    assert peak == metrics_tasks.MAX_CONCURRENT_NODE_COLLECTIONS
