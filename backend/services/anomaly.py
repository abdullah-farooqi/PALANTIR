import logging
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from sqlalchemy import select
from core.config import settings
from models.anomaly import AnomalyEvent
from models.metric import MetricSnapshot
from services.investigations import enqueue_investigation_async

logger = logging.getLogger(__name__)

BASELINE_WINDOW = timedelta(hours=6)
RECENT_WINDOW = timedelta(minutes=5)
BASELINE_GAP = timedelta(minutes=10)     # baseline ends before the recent window's neighbourhood
MIN_BASELINE_POINTS = 30                 # about 30 minutes of once-a-minute snapshots
MIN_RECENT_POINTS = 3

# context -> (minimum noise scale, minimum absolute level before it can count as anomalous)
CONTEXT_RULES = {
    "system.cpu": (5.0, 30.0),    # percent
    "system.ram": (3.0, 60.0),    # percent of total
    "system.load": (0.5, 1.0),    # 1-minute load average
}


def anomaly_score(recent: List[float], baseline: List[float], noise_floor: float, min_level: float) -> float:
    """0..1 score: how far the recent mean sits above the baseline (robust z-score), 0 when unremarkable."""
    if len(recent) < MIN_RECENT_POINTS or len(baseline) < MIN_BASELINE_POINTS:
        return 0.0
    level = sum(recent) / len(recent)
    if level < min_level:
        return 0.0
    median = statistics.median(baseline)
    mad = statistics.median(abs(value - median) for value in baseline)
    scale = max(1.4826 * mad, noise_floor)
    z = (level - median) / scale
    return round(min(1.0, max(0.0, z / 8.0)), 3)


def score_contexts(rows: List[dict], now: datetime) -> Dict[str, float]:
    """rows: dicts with collected_at, cpu_pct, ram_pct, load_avg (None when not measured)."""
    series: Dict[str, Dict[str, List[float]]] = {name: {"recent": [], "baseline": []} for name in CONTEXT_RULES}
    keys = {"system.cpu": "cpu_pct", "system.ram": "ram_pct", "system.load": "load_avg"}
    for row in rows:
        age = now - row["collected_at"]
        bucket = "recent" if age <= RECENT_WINDOW else "baseline" if age >= BASELINE_GAP else None
        if bucket is None:
            continue
        for name, key in keys.items():
            value = row.get(key)
            if value is not None:
                series[name][bucket].append(float(value))
    return {
        name: anomaly_score(data["recent"], data["baseline"], *CONTEXT_RULES[name])
        for name, data in series.items()
    }


class AnomalyService:
    """Detects sustained CPU / memory / load excursions from the node's own stored telemetry."""

    def __init__(self, node_url: Optional[str] = None):
        pass  # `node_url` kept for backwards compatibility; no external service is queried

    async def _in_cooldown(self, node_id: int, session) -> bool:
        cooldown_threshold = datetime.now(timezone.utc) - timedelta(minutes=settings.COOLDOWN_MINUTES)
        stmt = (
            select(AnomalyEvent)
            .where(AnomalyEvent.node_id == node_id, AnomalyEvent.detected_at >= cooldown_threshold)
            .limit(1)
        )
        res = session.execute(stmt)
        if hasattr(res, "__await__"):
            res = await res
        return res.scalar_one_or_none() is not None

    def _load_rows(self, node_id: int, session, now: datetime) -> List[dict]:
        stmt = (
            select(
                MetricSnapshot.collected_at, MetricSnapshot.cpu_pct, MetricSnapshot.ram_used_mb,
                MetricSnapshot.ram_total_mb, MetricSnapshot.load_avg,
            )
            .where(
                MetricSnapshot.node_id == node_id,
                MetricSnapshot.category == "system",
                MetricSnapshot.collected_at >= now - BASELINE_WINDOW,
                MetricSnapshot.data["sample"].as_string().is_(None),  # regular snapshots, not per-second rows
            )
            .order_by(MetricSnapshot.collected_at.asc())
        )
        rows = []
        for collected_at, cpu, used, total, load in session.execute(stmt).all():
            if collected_at.tzinfo is None:
                collected_at = collected_at.replace(tzinfo=timezone.utc)
            rows.append({
                "collected_at": collected_at,
                "cpu_pct": cpu,
                "ram_pct": (used / total * 100.0) if used is not None and total else None,
                "load_avg": load,
            })
        return rows

    async def evaluate_and_trigger(self, node_id: int, session):
        now = datetime.now(timezone.utc)
        rates = score_contexts(self._load_rows(node_id, session, now), now)
        anomalous = {ctx: score for ctx, score in rates.items() if score >= settings.ANOMALY_THRESHOLD}

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
            if hasattr(session, "commit"):
                res = session.commit()
                if hasattr(res, "__await__"):
                    await res
            try:
                _, dispatched = await enqueue_investigation_async(
                    session, node_id=node_id, trigger_type="anomaly", trigger_id=event.id,
                )
                if not dispatched:
                    logger.warning("Investigation dispatch failed for anomaly event %s", event.id)
            except Exception:
                logger.exception("Could not enqueue an investigation for anomaly event %s", event.id)
        except Exception as exc:
            if hasattr(session, "rollback"):
                res = session.rollback()
                if hasattr(res, "__await__"):
                    await res
            logger.error(f"Failed to persist anomaly event for node {node_id}: {exc}")
            raise
