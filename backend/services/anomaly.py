import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from sqlalchemy import select
from core.config import settings
from integrations.netdata.client import NetdataClient
from integrations.netdata.parsers import parse_anomaly_rates
from integrations.netdata.contexts import (
    NetworkContexts,
    SystemContexts,
    ProcessContexts,
    ContainerContexts,
)
from integrations.netdata.exceptions import NetdataUnavailable
from models.anomaly import AnomalyEvent

logger = logging.getLogger(__name__)

CONTEXTS_TO_WATCH = [
    NetworkContexts.BANDWIDTH,
    SystemContexts.CPU,
    SystemContexts.RAM,
    ProcessContexts.CPU,
    ContainerContexts.CPU,
]


class AnomalyService:
    def __init__(self, node_url: str):
        self.client = NetdataClient(base_url=node_url)

    async def _in_cooldown(self, node_id: int, session) -> bool:
        cooldown_threshold = datetime.now(timezone.utc) - timedelta(
            minutes=settings.COOLDOWN_MINUTES
        )
        stmt = (
            select(AnomalyEvent)
            .where(
                AnomalyEvent.node_id == node_id,
                AnomalyEvent.detected_at >= cooldown_threshold,
                AnomalyEvent.triggered_agent == True,
            )
            .limit(1)
        )
        res = session.execute(stmt)
        if hasattr(res, "__await__"):
            res = await res
        return res.scalar_one_or_none() is not None

    async def evaluate_and_trigger(self, node_id: int, session):
        try:
            raw = await self.client.get_anomaly_scores(CONTEXTS_TO_WATCH)
            rates = parse_anomaly_rates(raw)
        except NetdataUnavailable as e:
            logger.warning(f"Node {node_id} unreachable for anomaly eval: {e}")
            return
        except Exception as e:
            logger.error(f"Anomaly eval query error for node {node_id}: {e}")
            return

        if not rates:
            # ML still warming up (first 900s) — correct, not an error
            return

        anomalous = {
            ctx: score
            for ctx, score in rates.items()
            if score >= settings.ANOMALY_THRESHOLD
        }

        if len(anomalous) < settings.MIN_CONTEXTS_ANOMALOUS:
            return

        if await self._in_cooldown(node_id, session):
            logger.info(f"Node {node_id} anomaly detected but in cooldown. Skipping trigger.")
            return

        try:
            event = AnomalyEvent(
                node_id=node_id,
                contexts=list(anomalous.keys()),
                scores=anomalous,
                max_score=max(anomalous.values()),
                triggered_agent=False,
            )
            session.add(event)
            if hasattr(session, "flush"):
                res = session.flush()
                if hasattr(res, "__await__"):
                    await res

            # ── Extension point: wire your LangGraph agent here ──────────
            # from workers.agent_tasks import run_investigation
            # run_investigation.delay(
            #     node_id=node_id,
            #     trigger_type="anomaly",
            #     trigger_id=event.id,
            #     context_scores=anomalous,
            # )
            # ─────────────────────────────────────────────────────────────

            event.triggered_agent = True
            if hasattr(session, "commit"):
                res = session.commit()
                if hasattr(res, "__await__"):
                    await res
        except Exception as exc:
            if hasattr(session, "rollback"):
                res = session.rollback()
                if hasattr(res, "__await__"):
                    await res
            logger.error(f"Failed to persist anomaly event for node {node_id}: {exc}")
            raise
