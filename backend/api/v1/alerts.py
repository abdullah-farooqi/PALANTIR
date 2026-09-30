from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent

router = APIRouter(prefix="/nodes/{node_id}", tags=["Alerts & Anomalies"])


@router.get("/alerts")
async def get_alerts_history(
    node_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    stmt = (
        select(AlertEvent)
        .where(AlertEvent.node_id == node_id)
        .order_by(AlertEvent.received_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "received_at": r.received_at.isoformat(),
            "alert_name": r.alert_name,
            "chart": r.chart,
            "status": r.status,
            "value": r.value,
            "units": r.units,
            "triggered_agent": r.triggered_agent,
            "investigation_id": r.investigation_id,
        }
        for r in rows
    ]


@router.get("/alerts/active")
async def get_active_alerts(
    node_id: int,
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    """Returns only WARNING and CRITICAL alerts."""
    stmt = (
        select(AlertEvent)
        .where(
            AlertEvent.node_id == node_id,
            AlertEvent.status.in_(["WARNING", "CRITICAL"]),
        )
        .order_by(AlertEvent.received_at.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "received_at": r.received_at.isoformat(),
            "alert_name": r.alert_name,
            "chart": r.chart,
            "status": r.status,
            "value": r.value,
            "units": r.units,
            "triggered_agent": r.triggered_agent,
            "investigation_id": r.investigation_id,
        }
        for r in rows
    ]


@router.get("/anomalies")
async def get_anomalies_history(
    node_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    stmt = (
        select(AnomalyEvent)
        .where(AnomalyEvent.node_id == node_id)
        .order_by(AnomalyEvent.detected_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "detected_at": r.detected_at.isoformat(),
            "contexts": r.contexts,
            "scores": r.scores,
            "max_score": r.max_score,
            "triggered_agent": r.triggered_agent,
            "investigation_id": r.investigation_id,
        }
        for r in rows
    ]
