from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.cursors import decode_cursor, encode_cursor
from core.database import get_session
from models.log_event import LogEvent
from models.node import MonitoredNode

router = APIRouter(prefix="/logs", tags=["Fleet logs"])


def _cursor_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Cursor timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


@router.get("")
async def search_fleet_logs(
    node_id: int | None = Query(default=None, ge=1),
    q: str | None = Query(default=None, max_length=512, description="Full-text search over log messages"),
    service: str | None = Query(default=None, max_length=255),
    pid: int | None = Query(default=None, ge=1),
    source: str | None = Query(default=None, max_length=255),
    severity: str | None = Query(default=None, max_length=32),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if (since is not None and since.tzinfo is None) or (until is not None and until.tzinfo is None):
        raise HTTPException(status_code=400, detail="since and until must include a timezone")
    if since and until and since >= until:
        raise HTTPException(status_code=400, detail="since must be earlier than until")
    try:
        position = decode_cursor(cursor, {"event_at", "id"})
        cursor_at = _cursor_time(position["event_at"]) if position else None
        cursor_id = int(position["id"]) if position else None
        if position and cursor_id <= 0:
            raise ValueError("Cursor is invalid")
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "Cursor is invalid") from exc

    statement = select(LogEvent, MonitoredNode.hostname).join(
        MonitoredNode, MonitoredNode.id == LogEvent.node_id
    )
    if node_id is not None:
        statement = statement.where(LogEvent.node_id == node_id)
    if q:
        search_vector = func.to_tsvector("simple", func.coalesce(LogEvent.message, ""))
        query_vector = func.plainto_tsquery("simple", q)
        statement = statement.where(search_vector.op("@@")(query_vector))
    if service:
        statement = statement.where(LogEvent.service.ilike(service))
    if pid is not None:
        statement = statement.where(LogEvent.pid == pid)
    if source:
        statement = statement.where(LogEvent.source == source)
    if severity:
        statement = statement.where(LogEvent.severity == severity.lower())
    if since is not None:
        statement = statement.where(LogEvent.event_at >= since.astimezone(timezone.utc))
    if until is not None:
        statement = statement.where(LogEvent.event_at < until.astimezone(timezone.utc))
    if cursor_at is not None:
        statement = statement.where(or_(
            LogEvent.event_at < cursor_at,
            and_(LogEvent.event_at == cursor_at, LogEvent.id < cursor_id),
        ))
    statement = statement.order_by(LogEvent.event_at.desc(), LogEvent.id.desc()).limit(limit + 1)
    rows = (await session.execute(statement)).all()
    has_more = len(rows) > limit
    page = rows[:limit]
    items = [
        {
            "id": event.id,
            "event_id": event.event_id,
            "node_id": event.node_id,
            "hostname": hostname,
            "event_at": event.event_at.isoformat(),
            "source": event.source,
            "severity": event.severity,
            "service": event.service,
            "pid": event.pid,
            "message": event.message,
            "fields": event.fields,
            "parser": event.parser,
        }
        for event, hostname in page
    ]
    next_cursor = None
    if has_more and page:
        last_event = page[-1][0]
        next_cursor = encode_cursor({"event_at": last_event.event_at.isoformat(), "id": last_event.id})
    return {
        "schema_version": 1,
        "filters": {"node_id": node_id, "q": q, "service": service, "pid": pid,
                    "source": source, "severity": severity,
                    "since": since.isoformat() if since else None,
                    "until": until.isoformat() if until else None},
        "retention_days": settings.LOG_RETENTION_DAYS,
        "items": items,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }
