from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from models.log_event import LogEvent
from services.nodes import NodeService

router = APIRouter(prefix="/nodes/{node_id}/logs", tags=["Logs"])


@router.get("")
async def list_node_logs(
    node_id: int = Path(..., ge=1),
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    severity: Optional[str] = Query(default=None, max_length=32),
    source: Optional[str] = Query(default=None, max_length=255),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    stmt = select(LogEvent).where(LogEvent.node_id == node_id)
    if since:
        stmt = stmt.where(LogEvent.event_at >= since)
    if until:
        stmt = stmt.where(LogEvent.event_at <= until)
    if severity:
        stmt = stmt.where(LogEvent.severity == severity.lower())
    if source:
        stmt = stmt.where(LogEvent.source == source)
    stmt = stmt.order_by(LogEvent.event_at.desc(), LogEvent.id.desc()).offset(offset).limit(limit)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "node_id": node_id,
        "events": [
            {
                "id": row.id,
                "event_id": row.event_id,
                "timestamp": row.event_at.isoformat(),
                "source": row.source,
                "severity": row.severity,
                "service": row.service,
                "pid": row.pid,
                "message": row.message,
                "fields": row.fields,
                "parser": row.parser,
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset,
        "next_offset": offset + len(rows) if len(rows) == limit else None,
    }
