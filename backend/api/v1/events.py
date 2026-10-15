from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, and_, cast, literal, or_, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from core.cursors import decode_cursor, encode_cursor
from core.database import get_session
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.node import MonitoredNode

router = APIRouter(prefix="/events", tags=["Fleet events"])


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Cursor timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


@router.get("")
async def list_fleet_events(
    event_type: str = Query(default="all", pattern="^(all|alert|anomaly)$"),
    node_id: int | None = Query(default=None, ge=1),
    severity: str | None = Query(default=None, pattern="^(WARNING|CRITICAL|CLEAR)$"),
    min_score: float | None = Query(default=None, ge=0, le=1),
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
        position = decode_cursor(cursor, {"occurred_at", "event_type", "id"})
        cursor_time = _timestamp(position["occurred_at"]) if position else None
        cursor_type = position["event_type"] if position else None
        cursor_id = int(position["id"]) if position else None
        if position and cursor_type not in {"alert", "anomaly"}:
            raise ValueError("Cursor is invalid")
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "Cursor is invalid") from exc

    alert_query = (
        select(
            literal("alert").label("event_type"),
            AlertEvent.id.label("id"),
            AlertEvent.node_id.label("node_id"),
            MonitoredNode.hostname.label("hostname"),
            AlertEvent.received_at.label("occurred_at"),
            cast(AlertEvent.status, String).label("severity"),
            literal(None).label("score"),
        )
        .join(MonitoredNode, MonitoredNode.id == AlertEvent.node_id)
    )
    anomaly_query = (
        select(
            literal("anomaly").label("event_type"),
            AnomalyEvent.id.label("id"),
            AnomalyEvent.node_id.label("node_id"),
            MonitoredNode.hostname.label("hostname"),
            AnomalyEvent.detected_at.label("occurred_at"),
            literal(None, type_=String).label("severity"),
            AnomalyEvent.max_score.label("score"),
        )
        .join(MonitoredNode, MonitoredNode.id == AnomalyEvent.node_id)
    )
    if node_id is not None:
        alert_query = alert_query.where(AlertEvent.node_id == node_id)
        anomaly_query = anomaly_query.where(AnomalyEvent.node_id == node_id)
    if since is not None:
        alert_query = alert_query.where(AlertEvent.received_at >= since)
        anomaly_query = anomaly_query.where(AnomalyEvent.detected_at >= since)
    if until is not None:
        alert_query = alert_query.where(AlertEvent.received_at < until)
        anomaly_query = anomaly_query.where(AnomalyEvent.detected_at < until)
    if severity is not None:
        alert_query = alert_query.where(AlertEvent.status == severity)
    if min_score is not None:
        anomaly_query = anomaly_query.where(AnomalyEvent.max_score >= min_score)
    queries = []
    if event_type in {"all", "alert"}:
        queries.append(alert_query)
    if event_type in {"all", "anomaly"}:
        queries.append(anomaly_query)
    combined = union_all(*queries).subquery()
    statement = select(combined)
    if cursor_time is not None:
        statement = statement.where(or_(
            combined.c.occurred_at < cursor_time,
            and_(combined.c.occurred_at == cursor_time, combined.c.event_type > cursor_type),
            and_(combined.c.occurred_at == cursor_time, combined.c.event_type == cursor_type, combined.c.id < cursor_id),
        ))
    statement = statement.order_by(
        combined.c.occurred_at.desc(), combined.c.event_type.asc(), combined.c.id.desc()
    ).limit(limit + 1)
    rows = (await session.execute(statement)).mappings().all()
    has_more = len(rows) > limit
    page = rows[:limit]
    alert_ids = [row["id"] for row in page if row["event_type"] == "alert"]
    anomaly_ids = [row["id"] for row in page if row["event_type"] == "anomaly"]
    alerts = {
        row.id: row for row in (await session.execute(select(AlertEvent).where(AlertEvent.id.in_(alert_ids)))).scalars().all()
    } if alert_ids else {}
    anomalies = {
        row.id: row for row in (await session.execute(select(AnomalyEvent).where(AnomalyEvent.id.in_(anomaly_ids)))).scalars().all()
    } if anomaly_ids else {}

    items = []
    for key in page:
        item = {
            "event_type": key["event_type"],
            "id": key["id"],
            "node_id": key["node_id"],
            "hostname": key["hostname"],
            "occurred_at": key["occurred_at"].isoformat(),
        }
        event = alerts.get(key["id"]) if key["event_type"] == "alert" else anomalies.get(key["id"])
        if key["event_type"] == "alert" and event:
            item.update({"severity": event.status, "alert_name": event.alert_name, "chart": event.chart,
                         "value": event.value, "units": event.units, "investigation_id": event.investigation_id})
        elif event:
            item.update({"max_score": event.max_score, "contexts": event.contexts,
                         "scores": event.scores, "investigation_id": event.investigation_id})
        items.append(item)
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_cursor({
            "occurred_at": last["occurred_at"].isoformat(),
            "event_type": last["event_type"],
            "id": last["id"],
        })
    return {
        "schema_version": 1,
        "filters": {"event_type": event_type, "node_id": node_id, "severity": severity,
                    "min_score": min_score, "since": since.isoformat() if since else None,
                    "until": until.isoformat() if until else None},
        "items": items,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }
