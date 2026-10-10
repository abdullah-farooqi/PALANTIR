import logging
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from core.security import validate_netdata_url
from integrations.agent.client import AgentCollectorClient
from models.node import MonitoredNode
from models.alert import AlertEvent

logger = logging.getLogger(__name__)


class CollectorUnavailable(Exception):
    """The PALANTIR host collector could not be reached or returned an unusable response."""


class NodeService:
    @staticmethod
    async def register_node(
        hostname: str,
        session: AsyncSession,
        collector_url: str,
        os_type: str = "linux",
    ) -> MonitoredNode:
        """Register (or update) a node using PALANTIR host collector."""
        if not collector_url:
            raise ValueError("collector_url is required")
        collector_url = validate_netdata_url(collector_url)
        os_type = os_type.strip().lower() if os_type else "linux"

        try:
            collector = AgentCollectorClient(collector_url)
            info = await collector.info()
        except Exception as exc:
            logger.warning("Host collector unreachable during enrollment for %s: %s", hostname, exc)
            raise CollectorUnavailable(str(exc)[:300]) from exc
        try:
            capabilities = await collector.capabilities()
        except Exception as exc:  # the node is still usable; the next poll refreshes capabilities
            logger.warning("Could not read collector capabilities for %s: %s", hostname, exc)
            capabilities = None

        # Use the real distro reported by the host instead of the generic "linux" placeholder.
        os_release = info.get("os_release") if isinstance(info.get("os_release"), dict) else {}
        detected_os = os_release.get("ID") or os_release.get("NAME")
        if detected_os and isinstance(detected_os, str):
            os_type = detected_os.strip().lower()
        elif os_type not in {"linux", "windows"}:
            os_type = "linux"

        stmt = select(MonitoredNode).where(MonitoredNode.hostname == hostname)
        existing = (await session.execute(stmt)).scalar_one_or_none()

        if existing:
            existing.collector_url = collector_url
            if capabilities is not None:
                existing.capabilities = capabilities
            existing.os_type = os_type
            existing.active = True
            existing.last_seen_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(existing)
            return existing

        node = MonitoredNode(
            hostname=hostname,
            collector_url=collector_url,
            capabilities=capabilities,
            os_type=os_type,
            active=True,
            context_count=None,
            alert_count=None,
        )
        session.add(node)
        await session.commit()
        await session.refresh(node)
        return node

    @staticmethod
    async def list_nodes(session: AsyncSession, active_only: bool = True) -> List[MonitoredNode]:
        stmt = select(MonitoredNode)
        if active_only:
            stmt = stmt.where(MonitoredNode.active == True)
        stmt = stmt.order_by(MonitoredNode.hostname)
        result = await session.execute(stmt)
        nodes = list(result.scalars().all())

        # Efficiently calculate active alerts for all returned nodes
        if nodes:
            node_ids = [n.id for n in nodes]
            latest_transitions = (
                select(
                    AlertEvent.id.label("event_id"),
                    AlertEvent.node_id.label("node_id"),
                    AlertEvent.status.label("status"),
                    func.row_number()
                    .over(
                        partition_by=(
                            AlertEvent.node_id,
                            AlertEvent.alert_name,
                            AlertEvent.chart,
                        ),
                        order_by=(AlertEvent.received_at.desc(), AlertEvent.id.desc()),
                    )
                    .label("transition_rank"),
                )
                .where(AlertEvent.node_id.in_(node_ids))
                .subquery()
            )
            count_stmt = (
                select(
                    latest_transitions.c.node_id,
                    func.count().label("cnt"),
                )
                .where(
                    latest_transitions.c.transition_rank == 1,
                    latest_transitions.c.status.in_(["WARNING", "CRITICAL"]),
                )
                .group_by(latest_transitions.c.node_id)
            )
            counts_map = dict((await session.execute(count_stmt)).all())
            for n in nodes:
                cnt = counts_map.get(n.id, 0)
                n.active_alerts_count = cnt
                n._active_alerts_count = cnt

        return nodes

    @staticmethod
    async def get_node(node_id: int, session: AsyncSession) -> Optional[MonitoredNode]:
        stmt = select(MonitoredNode).where(MonitoredNode.id == node_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def deactivate_node(node_id: int, session: AsyncSession) -> bool:
        stmt = (
            update(MonitoredNode)
            .where(MonitoredNode.id == node_id)
            .values(active=False)
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount > 0
