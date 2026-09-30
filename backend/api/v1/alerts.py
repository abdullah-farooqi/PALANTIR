from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from services.nodes import NodeService

router = APIRouter(prefix="/nodes/{node_id}", tags=["Alerts & Anomalies"])


class AlertResponse(BaseModel):
    id: int
    received_at: str
    alert_name: str
    chart: str
    status: str
    value: Optional[float] = None
    units: Optional[str] = None
    triggered_agent: bool
    investigation_id: Optional[int] = None


class AnomalyResponse(BaseModel):
    id: int
    detected_at: str
    contexts: List[str]
    scores: Dict[str, float]
    max_score: float
    triggered_agent: bool
    investigation_id: Optional[int] = None


@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts_history(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    limit: int = Query(default=50, ge=1, le=500, description="Max alerts to retrieve"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

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


@router.get("/alerts/active", response_model=List[AlertResponse])
async def get_active_alerts(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    """Returns only WARNING and CRITICAL alerts."""
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

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


@router.get("/anomalies", response_model=List[AnomalyResponse])
async def get_anomalies_history(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    limit: int = Query(default=50, ge=1, le=500, description="Max anomalies to retrieve"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

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
