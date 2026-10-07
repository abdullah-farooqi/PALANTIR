import logging
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from core.security import validate_netdata_url
from integrations.netdata.client import NetdataClient
from integrations.netdata.exceptions import NetdataUnavailable
from integrations.agent.client import AgentCollectorClient
from models.node import MonitoredNode

logger = logging.getLogger(__name__)


class NodeService:
    @staticmethod
    async def register_node(
        hostname: str,
        netdata_url: str,
        os_type: str,
        session: AsyncSession,
        collector_url: Optional[str] = None,
    ) -> MonitoredNode:
        netdata_url = validate_netdata_url(netdata_url)
        os_type = os_type.strip().lower()
        if os_type not in {"linux", "windows"}:
            raise ValueError("os_type must be either 'linux' or 'windows'")
        client = NetdataClient(base_url=netdata_url)
        capabilities = None
        if collector_url:
            collector_url = validate_netdata_url(collector_url)
            try:
                collector = AgentCollectorClient(collector_url)
                await collector.info()
                capabilities = await collector.capabilities()
            except Exception as exc:
                logger.warning("Host collector unavailable during enrollment for %s: %s", hostname, exc)
                capabilities = {"status": "unavailable", "reason": str(exc)[:300]}
        
        # Probe connectivity
        await client.info()


        # Discover contexts
        try:
            contexts = await client.get_contexts()
            context_count = len(contexts)
        except Exception as e:
            logger.warning(f"Could not discover contexts on registration for {hostname}: {e}")
            context_count = None

        # Discover alerts
        try:
            alerts = await client.get_alerts(all_definitions=True)
            alert_count = len(alerts.get("alarms", {}))
        except Exception as e:
            logger.warning(f"Could not discover alerts on registration for {hostname}: {e}")
            alert_count = None

        # Check if node exists
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == hostname)
        existing = (await session.execute(stmt)).scalar_one_or_none()

        if existing:
            existing.netdata_url = netdata_url
            if collector_url is not None:
                existing.collector_url = collector_url
                existing.capabilities = capabilities
            existing.os_type = os_type
            existing.active = True
            existing.context_count = context_count
            existing.alert_count = alert_count
            existing.last_seen_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(existing)
            return existing

        node = MonitoredNode(
            hostname=hostname,
            netdata_url=netdata_url,
            collector_url=collector_url,
            capabilities=capabilities,
            os_type=os_type,
            active=True,
            context_count=context_count,
            alert_count=alert_count,
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
        return list(result.scalars().all())

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
