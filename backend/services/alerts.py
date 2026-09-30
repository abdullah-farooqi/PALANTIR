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

    async def receive_and_classify(self, payload, session):
        if hasattr(payload, "model_dump"):
            data = payload.model_dump()
        elif isinstance(payload, dict):
            data = payload
        else:
            logger.warning(f"Received alert with invalid payload type: {type(payload)}")
            return None

        hostname = data.get("node")
        if not hostname or not isinstance(hostname, str):
            logger.warning("Received alert payload without valid node hostname")
            return None

        # Sanitize hostname for logging (prevent log injection)
        safe_hostname = hostname.replace("\r", "").replace("\n", "")[:253]

        # Look up node by hostname
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == safe_hostname)
        result = await session.execute(stmt)
        node = result.scalar_one_or_none()

        if not node:
            logger.warning(f"Received alert for unregistered node: {safe_hostname}")
            return None

        raw_value = data.get("value")
        val = None
        if raw_value is not None:
            try:
                val = float(raw_value)
            except (ValueError, TypeError):
                val = None

        raw_status = str(data.get("status", "CLEAR")).upper().strip()
        if raw_status not in ("WARNING", "CRITICAL", "CLEAR"):
            if "CRIT" in raw_status:
                alert_status = "CRITICAL"
            elif "WARN" in raw_status:
                alert_status = "WARNING"
            else:
                alert_status = "CLEAR"
        else:
            alert_status = raw_status

        try:
            event = AlertEvent(
                node_id=node.id,
                alert_name=str(data.get("alert", "unknown"))[:255],
                chart=str(data.get("chart", "unknown"))[:255],
                status=alert_status,
                value=val,
                units=str(data["units"])[:64] if data.get("units") is not None else None,
                triggered_agent=False,
            )
            session.add(event)
            await session.flush()

            if alert_status in ("WARNING", "CRITICAL"):
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
        except Exception as exc:
            await session.rollback()
            logger.error(f"Failed to record alert event for node {safe_hostname}: {exc}")
            raise

