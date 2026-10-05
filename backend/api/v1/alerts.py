from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import func, select
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
    investigation_id: Optional[int] = None


class AnomalyResponse(BaseModel):
    id: int
    detected_at: str
    contexts: List[str]
    scores: Dict[str, float]
    max_score: float
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
            "investigation_id": r.investigation_id,
        }
        for r in rows
    ]


@router.get("/alerts/active", response_model=List[AlertResponse])
async def get_active_alerts(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    """Return the latest non-clear transition for each alert on this node."""
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    # AlertEvent is an append-only transition log. Rank each alert identity by
    # receipt time (and ID to break timestamp ties), then retain only identities
    # whose newest transition is still WARNING or CRITICAL.
    latest_transitions = (
        select(
            AlertEvent.id.label("event_id"),
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
        .where(AlertEvent.node_id == node_id)
        .subquery()
    )
    stmt = (
        select(AlertEvent)
        .join(latest_transitions, AlertEvent.id == latest_transitions.c.event_id)
        .where(
            latest_transitions.c.transition_rank == 1,
            AlertEvent.status.in_(["WARNING", "CRITICAL"]),
        )
        .order_by(AlertEvent.received_at.desc(), AlertEvent.id.desc())
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
            "investigation_id": r.investigation_id,
        }
        for r in rows
    ]
