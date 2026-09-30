from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from models.investigation import AgentInvestigation
from services.nodes import NodeService

router = APIRouter(prefix="/investigations", tags=["Investigations"])


class InvestigationCreateRequest(BaseModel):
    node_id: int = Field(..., ge=1, description="Monitored node ID")
    trigger_type: str = Field(default="manual", pattern=r"^(manual|alert|anomaly)$")
    trigger_id: Optional[int] = Field(default=None, ge=1)

    model_config = {"extra": "forbid"}


class InvestigationResponse(BaseModel):
    id: int
    node_id: int
    started_at: str
    completed_at: Optional[str] = None
    trigger_type: str
    trigger_id: Optional[int] = None
    status: str
    summary: Optional[str] = None
    raw_output: Optional[Any] = None


class InvestigationCreatedResponse(BaseModel):
    id: int
    status: str
    message: str


@router.get("", response_model=List[InvestigationResponse])
async def list_investigations(
    limit: int = Query(default=50, ge=1, le=500, description="Max investigations to retrieve"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    stmt = (
        select(AgentInvestigation)
        .order_by(AgentInvestigation.started_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "node_id": r.node_id,
            "started_at": r.started_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "trigger_type": r.trigger_type,
            "trigger_id": r.trigger_id,
            "status": r.status,
            "summary": r.summary,
            "raw_output": r.raw_output,
        }
        for r in rows
    ]


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: int = Path(..., ge=1, description="Investigation ID"),
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    stmt = select(AgentInvestigation).where(AgentInvestigation.id == investigation_id)
    inv = (await session.execute(stmt)).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    return {
        "id": inv.id,
        "node_id": inv.node_id,
        "started_at": inv.started_at.isoformat(),
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
        "trigger_type": inv.trigger_type,
        "trigger_id": inv.trigger_id,
        "status": inv.status,
        "summary": inv.summary,
        "raw_output": inv.raw_output,
    }


@router.post("", response_model=InvestigationCreatedResponse, status_code=status.HTTP_201_CREATED)
async def trigger_investigation(
    req: InvestigationCreateRequest,
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    node = await NodeService.get_node(req.node_id, session)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {req.node_id} not found",
        )

    inv = AgentInvestigation(
        node_id=req.node_id,
        trigger_type=req.trigger_type,
        trigger_id=req.trigger_id,
        status="running",
    )
    session.add(inv)
    await session.commit()
    await session.refresh(inv)

    # ── Extension point: dispatch LangGraph agent task ────────────
    # from workers.agent_tasks import run_investigation
    # run_investigation.delay(investigation_id=inv.id, node_id=req.node_id)
    # ─────────────────────────────────────────────────────────────

    return {
        "id": inv.id,
        "status": inv.status,
        "message": "Investigation triggered successfully",
    }
