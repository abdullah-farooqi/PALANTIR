import logging
from sqlalchemy import select
from models.node import MonitoredNode
from models.alert import AlertEvent

logger = logging.getLogger(__name__)


class AlertService:
    """
    Push flow — receives Netdata webhook, persists, triggers agent.
    Extension point: swap run_investigation.delay() for your LangGraph call.
    """

    async def receive_and_classify(self, payload: dict, session):
        hostname = payload.get("node")
        if not hostname:
            logger.warning("Received alert payload without node hostname")
            return None

        # Look up node by hostname
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == hostname)
        result = await session.execute(stmt)
        node = result.scalar_one_or_none()

        if not node:
            logger.warning(f"Received alert for unregistered node: {hostname}")
            return None

        event = AlertEvent(
            node_id=node.id,
            alert_name=payload.get("alert", "unknown"),
            chart=payload.get("chart", "unknown"),
            status=payload.get("status", "CLEAR"),
            value=payload.get("value"),
            units=payload.get("units"),
            triggered_agent=False,
        )
        session.add(event)
        await session.flush()

        if payload.get("status") in ("WARNING", "CRITICAL"):
            # ── Extension point: wire your LangGraph agent here ──────
            # from workers.agent_tasks import run_investigation
            # run_investigation.delay(
            #     node_id=node.id,
            #     trigger_type="alert",
            #     trigger_id=event.id,
            # )
            # ─────────────────────────────────────────────────────────
            event.triggered_agent = True

        await session.commit()
        return event
