from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from models.metric import MetricSnapshot
from services.nodes import NodeService

router = APIRouter(prefix="/nodes/{node_id}/metrics", tags=["Metrics"])


class MetricSnapshotItem(BaseModel):
    id: int
    collected_at: str
    category: str
    data: Any


class CategoryMetricResponse(BaseModel):
    collected_at: Optional[str] = None
    data: Optional[Any] = None


@router.get("", response_model=Dict[str, CategoryMetricResponse])
async def get_latest_metrics_all(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    """Returns the latest metric snapshot for all categories for this node."""
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    categories = ["network", "system", "processes", "containers"]
    result = {}
    for cat in categories:
        stmt = (
            select(MetricSnapshot)
            .where(
                MetricSnapshot.node_id == node_id,
                MetricSnapshot.category == cat,
            )
            .order_by(MetricSnapshot.collected_at.desc())
            .limit(1)
        )
        snap = (await session.execute(stmt)).scalar_one_or_none()
        result[cat] = {
            "collected_at": snap.collected_at.isoformat() if snap else None,
            "data": snap.data if snap else None,
        }
    return result


@router.get("/{category}", response_model=List[MetricSnapshotItem])
async def get_latest_metrics_by_category(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    category: str = Path(..., description="Metric category"),
    limit: int = Query(default=1, ge=1, le=100, description="Max snapshots to retrieve"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    valid_categories = {"network", "system", "processes", "containers"}
    if category not in valid_categories:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category '{category}'. Must be one of {valid_categories}",
        )

    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    stmt = (
        select(MetricSnapshot)
        .where(
            MetricSnapshot.node_id == node_id,
            MetricSnapshot.category == category,
        )
        .order_by(MetricSnapshot.collected_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "collected_at": r.collected_at.isoformat(),
            "category": r.category,
            "data": r.data,
        }
        for r in rows
    ]
