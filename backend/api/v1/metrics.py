from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import Float, and_, cast, extract, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from core.config import settings
from core.cursors import decode_cursor, encode_cursor
from core.database import get_session
from models.metric import MetricSnapshot
from services.nodes import NodeService

router = APIRouter(prefix="/nodes/{node_id}/metrics", tags=["Metrics"])
SERIES_FIELDS = ("cpu_pct", "ram_used_mb", "ram_total_mb", "load_avg", "swap_used_mb")
VALID_SOURCES = {"netdata", "palantir-agent"}


class MetricSnapshotItem(BaseModel):
    id: int
    collected_at: str
    category: str
    data: Any
    cpu_pct: Optional[float] = None
    ram_used_mb: Optional[float] = None
    ram_total_mb: Optional[float] = None
    load_avg: Optional[float] = None
    swap_used_mb: Optional[float] = None
    top_processes: Optional[List[Dict[str, Any]]] = None


class CategoryMetricResponse(BaseModel):
    collected_at: Optional[str] = None
    data: Optional[Any] = None
    cpu_pct: Optional[float] = None
    ram_used_mb: Optional[float] = None
    ram_total_mb: Optional[float] = None
    load_avg: Optional[float] = None
    swap_used_mb: Optional[float] = None
    top_processes: Optional[List[Dict[str, Any]]] = None
    sources: Optional[Dict[str, List[Any]]] = None


@router.get("", response_model=Dict[str, CategoryMetricResponse])
async def get_latest_metrics_all(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    """Returns the latest metric snapshot for all categories for this node."""
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    categories = ["system", "storage", "network", "services", "processes", "connections", "containers", "vms"]
    result = {}
    for cat in categories:
        stmt = (
            select(MetricSnapshot)
            .where(
                MetricSnapshot.node_id == node_id,
                MetricSnapshot.category == cat,
            )
            .order_by(MetricSnapshot.collected_at.desc(), MetricSnapshot.id.desc())
            .limit(200)
        )
        snapshots = (await session.execute(stmt)).scalars().all()
        snap = snapshots[0] if snapshots else None
        sources: Dict[str, List[Any]] = {}
        for item in snapshots:
            source = item.data.get("source", "netdata") if isinstance(item.data, dict) else "unknown"
            sources.setdefault(str(source), []).append(item.data)
        result[cat] = {
            "collected_at": snap.collected_at.isoformat() if snap else None,
            "data": snap.data if snap else None,
            "cpu_pct": next((item.cpu_pct for item in snapshots if isinstance(item.data, dict) and item.data.get("source") == "netdata" and item.cpu_pct is not None), snap.cpu_pct if snap else None),
            "ram_used_mb": next((item.ram_used_mb for item in snapshots if isinstance(item.data, dict) and item.data.get("source") == "netdata" and item.ram_used_mb is not None), snap.ram_used_mb if snap else None),
            "ram_total_mb": next((item.ram_total_mb for item in snapshots if isinstance(item.data, dict) and item.data.get("source") == "netdata" and item.ram_total_mb is not None), snap.ram_total_mb if snap else None),
            "load_avg": next((item.load_avg for item in snapshots if isinstance(item.data, dict) and item.data.get("source") == "netdata" and item.load_avg is not None), snap.load_avg if snap else None),
            "swap_used_mb": next((item.swap_used_mb for item in snapshots if isinstance(item.data, dict) and item.data.get("source") == "netdata" and item.swap_used_mb is not None), snap.swap_used_mb if snap else None),
            "top_processes": next((item.top_processes for item in snapshots if isinstance(item.data, dict) and item.data.get("source") == "netdata" and item.top_processes is not None), snap.top_processes if snap else None),
            "sources": sources,
        }
    return result


@router.get("/{category}", response_model=List[MetricSnapshotItem])
async def get_latest_metrics_by_category(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    category: str = Path(..., description="Metric category"),
    limit: int = Query(default=1, ge=1, le=100, description="Max snapshots to retrieve"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    valid_categories = {"network", "system", "storage", "services", "processes", "connections", "containers", "vms"}
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
        .order_by(MetricSnapshot.collected_at.desc(), MetricSnapshot.id.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "collected_at": r.collected_at.isoformat(),
            "category": r.category,
            "data": r.data,
            "cpu_pct": r.cpu_pct,
            "ram_used_mb": r.ram_used_mb,
            "ram_total_mb": r.ram_total_mb,
            "load_avg": r.load_avg,
            "swap_used_mb": r.swap_used_mb,
            "top_processes": r.top_processes,
        }
        for r in rows
    ]


@router.get("/{category}/series")
async def get_metric_series(
    node_id: int = Path(..., ge=1),
    category: str = Path(...),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    source: Optional[str] = Query(default=None, pattern="^(netdata|palantir-agent)$"),
    limit: int = Query(default=250, ge=1, le=1000),
    cursor: Optional[str] = None,
    bucket_seconds: Optional[int] = Query(default=None, ge=10, le=86400),
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    valid_categories = {"network", "system", "storage", "services", "processes", "connections", "containers", "vms"}
    if category not in valid_categories:
        raise HTTPException(status_code=400, detail="Unknown metric category")
    if source is not None and source not in VALID_SOURCES:
        raise HTTPException(status_code=400, detail="Unknown metric source")
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    now = datetime.now(timezone.utc)
    retention_hours = settings.METRICS_RETENTION_HOURS
    earliest = now - timedelta(hours=retention_hours)
    if (since is not None and since.tzinfo is None) or (until is not None and until.tzinfo is None):
        raise HTTPException(status_code=400, detail="since and until must include a timezone")
    since = since.astimezone(timezone.utc) if since else earliest
    until = until.astimezone(timezone.utc) if until else now
    if since >= until:
        raise HTTPException(status_code=400, detail="since must be earlier than until")
    if since < earliest:
        raise HTTPException(status_code=400, detail="Requested window begins before metric retention")
    if until - since > timedelta(hours=retention_hours):
        raise HTTPException(status_code=400, detail="Requested window exceeds metric retention")
    source_expr = func.coalesce(MetricSnapshot.data["source"].as_string(), "netdata")
    filters = [
        MetricSnapshot.node_id == node_id,
        MetricSnapshot.category == category,
        MetricSnapshot.collected_at >= since,
        MetricSnapshot.collected_at < until,
    ]
    if source:
        filters.append(source_expr == source)

    try:
        if bucket_seconds is None:
            position = decode_cursor(cursor, {"collected_at", "id"})
            if position:
                cursor_time = datetime.fromisoformat(position["collected_at"].replace("Z", "+00:00"))
                if cursor_time.tzinfo is None:
                    raise ValueError("Cursor timestamp must include a timezone")
                filters.append(or_(
                    MetricSnapshot.collected_at < cursor_time,
                    and_(MetricSnapshot.collected_at == cursor_time, MetricSnapshot.id < int(position["id"])),
                ))
            statement = (
                select(MetricSnapshot, source_expr.label("source_name"))
                .where(*filters)
                .order_by(MetricSnapshot.collected_at.desc(), MetricSnapshot.id.desc())
                .limit(limit + 1)
            )
            result_rows = (await session.execute(statement)).all()
            has_more = len(result_rows) > limit
            rows = result_rows[:limit]
            items = []
            for snapshot, source_name in rows:
                data = snapshot.data if isinstance(snapshot.data, dict) else {"value": snapshot.data}
                items.append({
                    "schema_version": 1,
                    "node_id": snapshot.node_id,
                    "category": snapshot.category,
                    "source": source_name,
                    "collected_at": snapshot.collected_at.isoformat(),
                    "collection_status": "available",
                    "data": data,
                    "metrics": {field: getattr(snapshot, field) for field in SERIES_FIELDS
                                if getattr(snapshot, field) is not None},
                })
            next_cursor = None
            if has_more and rows:
                snapshot, _ = rows[-1]
                next_cursor = encode_cursor({"collected_at": snapshot.collected_at.isoformat(), "id": snapshot.id})
            aggregation = None
        else:
            position = decode_cursor(cursor, {"bucket_at", "source"})
            bucket_expr = func.to_timestamp(cast(
                func.floor(extract("epoch", MetricSnapshot.collected_at) / bucket_seconds) * bucket_seconds,
                Float,
            ))
            if position:
                bucket_time = datetime.fromisoformat(position["bucket_at"].replace("Z", "+00:00"))
                if bucket_time.tzinfo is None or position["source"] not in VALID_SOURCES:
                    raise ValueError("Cursor is invalid")
                filters.append(or_(
                    bucket_expr < bucket_time,
                    and_(bucket_expr == bucket_time, source_expr > position["source"]),
                ))
            aggregates = [
                func.count(MetricSnapshot.id).label("sample_count"),
                *[
                    aggregate.label(f"{field}_{aggregate_name}")
                    for field in SERIES_FIELDS
                    for aggregate_name, aggregate in (
                        ("avg", func.avg(getattr(MetricSnapshot, field))),
                        ("min", func.min(getattr(MetricSnapshot, field))),
                        ("max", func.max(getattr(MetricSnapshot, field))),
                    )
                ],
            ]
            statement = (
                select(bucket_expr.label("bucket_at"), source_expr.label("source_name"), *aggregates)
                .where(*filters)
                .group_by(bucket_expr, source_expr)
                .order_by(bucket_expr.desc(), source_expr.asc())
                .limit(limit + 1)
            )
            result_rows = (await session.execute(statement)).mappings().all()
            has_more = len(result_rows) > limit
            rows = result_rows[:limit]
            items = []
            for row in rows:
                values = {}
                for field in SERIES_FIELDS:
                    field_values = {
                        key: row[f"{field}_{key}"]
                        for key in ("avg", "min", "max")
                        if row[f"{field}_{key}"] is not None
                    }
                    if field_values:
                        values[field] = field_values
                items.append({
                    "schema_version": 1,
                    "node_id": node_id,
                    "category": category,
                    "source": row["source_name"],
                    "bucket_at": row["bucket_at"].isoformat(),
                    "bucket_seconds": bucket_seconds,
                    "sample_count": row["sample_count"],
                    "metrics": values,
                })
            next_cursor = None
            if has_more and rows:
                last = rows[-1]
                next_cursor = encode_cursor({"bucket_at": last["bucket_at"].isoformat(), "source": last["source_name"]})
            aggregation = {"method": "time_bucket", "bucket_seconds": bucket_seconds,
                           "fields": list(SERIES_FIELDS), "grouped_by": ["source"]}
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "Cursor is invalid") from exc

    return {
        "schema_version": 1,
        "node_id": node_id,
        "category": category,
        "source": source,
        "window": {"since": since.isoformat(), "until": until.isoformat(),
                   "retention_hours": retention_hours, "earliest_available_at": earliest.isoformat()},
        "aggregation": aggregation,
        "items": items,
        "paging": {"limit": limit, "has_more": has_more, "next_cursor": next_cursor},
    }
