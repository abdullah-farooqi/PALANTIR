import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from core.database import get_sync_session, AsyncSessionLocal
from models.node import MonitoredNode
from models.metric import MetricSnapshot
from models.anomaly import AnomalyEvent
from services.metrics import MetricsService
from services.anomaly import AnomalyService
from workers.maintenance_tasks import prune_old_snapshots


@pytest.fixture
def local_node_sync():
    with get_sync_session() as session:
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == "local-node")
        node = session.execute(stmt).scalar_one_or_none()
        if not node:
            node = MonitoredNode(
                hostname="local-node",
                netdata_url="http://netdata:19999",
                os_type="linux",
                active=True,
            )
            session.add(node)
            session.commit()
            session.refresh(node)
        return node


@pytest.mark.asyncio
async def test_metrics_service_collect_and_persist(local_node_sync):
    svc = MetricsService("http://mock-node:19999")
    mock_data = [{"timestamp": 1727000000, "user": 10.5, "system": 5.2}]

    with patch.object(svc, "collect_network", new=AsyncMock(return_value=mock_data)), \
         patch.object(svc, "collect_system", new=AsyncMock(return_value=mock_data)), \
         patch.object(svc, "collect_processes", new=AsyncMock(return_value=[])), \
         patch.object(svc, "collect_containers", new=AsyncMock(return_value=[])):

        with get_sync_session() as session:
            await svc.collect_and_persist(local_node_sync.id, session)

        # Verify snapshots written
        async with AsyncSessionLocal() as session:
            stmt = (
                select(MetricSnapshot)
                .where(
                    MetricSnapshot.node_id == local_node_sync.id,
                    MetricSnapshot.category == "system",
                )
                .order_by(MetricSnapshot.collected_at.desc())
                .limit(1)
            )
            snap = (await session.execute(stmt)).scalar_one_or_none()
            assert snap is not None
            assert snap.data["user"] == 10.5


@pytest.mark.asyncio
async def test_anomaly_service_evaluate_and_trigger(local_node_sync):
    svc = AnomalyService("http://mock-node:19999")

    # Mock high anomaly scores exceeding ANOMALY_THRESHOLD (0.7) for >= 2 contexts
    mock_weights_resp = {
        "net.net": 0.85,
        "system.cpu": 0.92,
        "system.ram": 0.10,
    }

    with patch.object(svc.client, "get_anomaly_scores", new=AsyncMock(return_value=None)), \
         patch("services.anomaly.parse_anomaly_rates", return_value=mock_weights_resp):

        with get_sync_session() as session:
            await svc.evaluate_and_trigger(local_node_sync.id, session)

        # Verify AnomalyEvent was created
        async with AsyncSessionLocal() as session:
            stmt = (
                select(AnomalyEvent)
                .where(AnomalyEvent.node_id == local_node_sync.id)
                .order_by(AnomalyEvent.detected_at.desc())
                .limit(1)
            )
            event = (await session.execute(stmt)).scalar_one_or_none()
            assert event is not None
            assert event.max_score == 0.92
            assert event.triggered_agent is True
            assert "net.net" in event.contexts
            assert "system.cpu" in event.contexts


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
