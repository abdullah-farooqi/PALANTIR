from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from core.api_auth import require_admin
from core.cursors import decode_cursor, encode_cursor
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.investigation import AgentInvestigation
from services.nodes import NodeService
from services.investigations import enqueue_investigation_async

router = APIRouter(prefix="/investigations", tags=["Investigations"])


class InvestigationCreateRequest(BaseModel):
    node_id: int = Field(..., ge=1, description="Monitored node ID")
    trigger_type: str = Field(default="manual", pattern=r"^(manual|alert|anomaly)$")
    trigger_id: Optional[int] = Field(default=None, ge=1)

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_trigger_reference(self):
        if self.trigger_type == "manual" and self.trigger_id is not None:
            raise ValueError("Manual investigations cannot include trigger_id")
        if self.trigger_type in {"alert", "anomaly"} and self.trigger_id is None:
            raise ValueError("Alert and anomaly investigations require trigger_id")
        return self


class InvestigationResponse(BaseModel):
    id: int
    node_id: int
    job_id: Optional[str] = None
    queued_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    trigger_type: str
    trigger_id: Optional[int] = None
    status: str
    progress: int = 0
    queue_delay_ms: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    summary: Optional[str] = None
    raw_output: Optional[Any] = None


def _serialize(row: AgentInvestigation) -> dict[str, Any]:
    status_value = row.status
    summary = row.summary
    if status_value == "running" and not row.job_id:
        status_value = "failed"
        summary = summary or "Legacy investigation was never dispatched to a worker."
    return {
        "id": row.id,
        "node_id": row.node_id,
        "job_id": row.job_id,
        "queued_at": row.queued_at.isoformat() if row.queued_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "trigger_type": row.trigger_type,
        "trigger_id": row.trigger_id,
        "status": status_value,
        "progress": row.progress,
        "queue_delay_ms": row.queue_delay_ms,
        "error_code": row.error_code,
        "error_message": row.error_message,
        "summary": summary,
        "raw_output": row.raw_output,
    }


@router.get("", response_model=List[InvestigationResponse])
async def list_investigations(
    limit: int = Query(default=50, ge=1, le=500, description="Max investigations to retrieve"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    stmt = (
        select(AgentInvestigation)
        .order_by(func.coalesce(AgentInvestigation.started_at, AgentInvestigation.queued_at).desc(), AgentInvestigation.id.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [_serialize(row) for row in rows]


@router.get("/search")
async def search_investigations(
    node_id: int | None = Query(default=None, ge=1),
    status_filter: str | None = Query(
        default=None,
        alias="status",
        pattern="^(queued|running|complete|failed|cancelled)$",
    ),
    trigger_type: str | None = Query(default=None, pattern="^(manual|alert|anomaly)$"),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if (since is not None and since.tzinfo is None) or (until is not None and until.tzinfo is None):
        raise HTTPException(status_code=400, detail="since and until must include a timezone")
    if since and until and since >= until:
        raise HTTPException(status_code=400, detail="since must be earlier than until")
    sort_time = func.coalesce(AgentInvestigation.started_at, AgentInvestigation.queued_at)
    try:
        position = decode_cursor(cursor, {"timestamp", "id"})
        cursor_time = datetime.fromisoformat(position["timestamp"].replace("Z", "+00:00")) if position else None
        cursor_id = int(position["id"]) if position else None
        if position and (cursor_time.tzinfo is None or cursor_id <= 0):
            raise ValueError("Cursor is invalid")
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "Cursor is invalid") from exc

    statement = select(AgentInvestigation)
    if node_id is not None:
        statement = statement.where(AgentInvestigation.node_id == node_id)
    if status_filter is not None:
        statement = statement.where(AgentInvestigation.status == status_filter)
    if trigger_type is not None:
        statement = statement.where(AgentInvestigation.trigger_type == trigger_type)
    if since is not None:
        statement = statement.where(sort_time >= since.astimezone(timezone.utc))
    if until is not None:
        statement = statement.where(sort_time < until.astimezone(timezone.utc))
    if cursor_time is not None:
        statement = statement.where(or_(
            sort_time < cursor_time,
            and_(sort_time == cursor_time, AgentInvestigation.id < cursor_id),
        ))
    statement = statement.order_by(sort_time.desc(), AgentInvestigation.id.desc()).limit(limit + 1)
    rows = (await session.execute(statement)).scalars().all()
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_cursor({
            "timestamp": (last.started_at or last.queued_at).isoformat(),
            "id": last.id,
        })
    return {
        "schema_version": 1,
        "filters": {"node_id": node_id, "status": status_filter, "trigger_type": trigger_type,
                    "since": since.isoformat() if since else None,
                    "until": until.isoformat() if until else None},
        "items": [_serialize(row) for row in page],
        "has_more": has_more,
        "next_cursor": next_cursor,
    }


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: int = Path(..., ge=1, description="Investigation ID"),
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    stmt = select(AgentInvestigation).where(AgentInvestigation.id == investigation_id)
    inv = (await session.execute(stmt)).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    return _serialize(inv)


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=InvestigationResponse,
    responses={503: {"description": "Investigation job could not be queued"}},
)
async def trigger_investigation(
    req: InvestigationCreateRequest,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_admin),
) -> Dict[str, Any]:
    node = await NodeService.get_node(req.node_id, session)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {req.node_id} not found",
        )

    if req.trigger_type == "alert":
        trigger = (await session.execute(select(AlertEvent).where(
            AlertEvent.id == req.trigger_id, AlertEvent.node_id == req.node_id
        ))).scalar_one_or_none()
    elif req.trigger_type == "anomaly":
        trigger = (await session.execute(select(AnomalyEvent).where(
            AnomalyEvent.id == req.trigger_id, AnomalyEvent.node_id == req.node_id
        ))).scalar_one_or_none()
    else:
        trigger = None
    if req.trigger_type in {"alert", "anomaly"} and trigger is None:
        raise HTTPException(status_code=404, detail="Trigger event not found for this node")

    investigation, dispatched = await enqueue_investigation_async(
        session,
        node_id=req.node_id,
        trigger_type=req.trigger_type,
        trigger_id=req.trigger_id,
    )
    if not dispatched:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"message": "Investigation dispatch failed", "investigation_id": investigation.id},
        )
    return _serialize(investigation)
