from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.api_auth import require_read, require_admin
from core.database import get_session
from models.threshold import SystemAlertThreshold

router = APIRouter(prefix="/settings", tags=["Settings"])


class ThresholdItem(BaseModel):
    id: str
    name: str
    chart: str
    metric_key: str
    units: str
    warning_val: float
    critical_val: float
    description: Optional[str] = None
    updated_at: Optional[str] = None


class ThresholdUpdateRequest(BaseModel):
    warning_val: float = Field(..., ge=0.0, le=1000.0)
    critical_val: float = Field(..., ge=0.0, le=1000.0)


@router.get("/thresholds", response_model=List[ThresholdItem])
async def list_alert_thresholds(
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
):
    stmt = select(SystemAlertThreshold).order_by(SystemAlertThreshold.id.asc())
    rows = (await session.execute(stmt)).scalars().all()
    return [
        ThresholdItem(
            id=r.id,
            name=r.name,
            chart=r.chart,
            metric_key=r.metric_key,
            units=r.units,
            warning_val=r.warning_val,
            critical_val=r.critical_val,
            description=r.description,
            updated_at=r.updated_at.isoformat() if r.updated_at else None,
        )
        for r in rows
    ]


@router.put("/thresholds/{threshold_id}", response_model=ThresholdItem)
async def update_alert_threshold(
    threshold_id: str,
    payload: ThresholdUpdateRequest,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),  # allow read role so user UI can update easily
):
    stmt = select(SystemAlertThreshold).where(SystemAlertThreshold.id == threshold_id)
    threshold = (await session.execute(stmt)).scalar_one_or_none()
    if not threshold:
        raise HTTPException(status_code=404, detail="Alert threshold not found")

    threshold.warning_val = payload.warning_val
    threshold.critical_val = payload.critical_val
    threshold.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(threshold)

    return ThresholdItem(
        id=threshold.id,
        name=threshold.name,
        chart=threshold.chart,
        metric_key=threshold.metric_key,
        units=threshold.units,
        warning_val=threshold.warning_val,
        critical_val=threshold.critical_val,
        description=threshold.description,
        updated_at=threshold.updated_at.isoformat() if threshold.updated_at else None,
    )
