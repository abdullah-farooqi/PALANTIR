import logging
from datetime import datetime, timezone
from sqlalchemy import select
from models.node import MonitoredNode
from models.alert import AlertEvent
from services.investigations import enqueue_investigation_async, request_pcap_evidence_for_alert

logger = logging.getLogger(__name__)


class AlertService:
    """
    Push flow — receives and persists alert transitions.
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
                logger.warning(
                    "Ignoring alert webhook with unsupported status %r for %s",
                    raw_status[:32],
                    safe_hostname,
                )
                return None
        else:
            alert_status = raw_status

        event_at = None
        try:
            if data.get("timestamp") is not None:
                event_at = datetime.fromtimestamp(float(data["timestamp"]), timezone.utc)
        except (OverflowError, OSError, TypeError, ValueError):
            logger.warning("Ignoring invalid source timestamp for alert on %s", safe_hostname)

        try:
            event = AlertEvent(
                node_id=node.id,
                event_at=event_at,
                alert_name=str(data.get("alert", "unknown"))[:255],
                chart=str(data.get("chart", "unknown"))[:255],
                status=alert_status,
                value=val,
                units=str(data["units"])[:64] if data.get("units") is not None else None,
                triggered_agent=False,
            )
            session.add(event)
            await session.flush()

            await session.commit()
            if alert_status in {"WARNING", "CRITICAL"}:
                try:
                    investigation, _dispatched = await enqueue_investigation_async(
                        session,
                        node_id=node.id,
                        trigger_type="alert",
                        trigger_id=event.id,
                    )
                    await request_pcap_evidence_for_alert(
                        session,
                        event_id=event.id,
                        node_id=node.id,
                        investigation_id=investigation.id,
                    )
                except Exception:
                    logger.exception("Could not enqueue investigation or PCAP evidence for alert event %s", event.id)
            return event
        except Exception as exc:
            await session.rollback()
            logger.error(f"Failed to record alert event for node {safe_hostname}: {exc}")
            raise
