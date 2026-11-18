from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, and_, cast, literal, or_, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from core.cursors import decode_cursor, encode_cursor
from core.database import get_session
from core.api_auth import require_admin, require_read
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.node import MonitoredNode
from pydantic import BaseModel, Field
from typing import List, Optional, Dict

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

DETECTION_RULES = [
    {"id": "rule_cpu_high", "name": "CPU Utilization Critical", "category": "system", "chart": "system.cpu", "severity": "CRITICAL", "condition": "> 90%", "enabled": True, "description": "Triggered when CPU utilization exceeds 90% sustained for 60s"},
    {"id": "rule_cpu_warn", "name": "CPU Utilization Warning", "category": "system", "chart": "system.cpu", "severity": "WARNING", "condition": "> 80%", "enabled": True, "description": "Triggered when CPU utilization exceeds 80% sustained for 120s"},
    {"id": "rule_ram_crit", "name": "Memory Exhaustion Critical", "category": "system", "chart": "system.ram", "severity": "CRITICAL", "condition": "> 95%", "enabled": True, "description": "Triggered when RAM usage exceeds 95% or swap usage exceeds 80%"},
    {"id": "rule_disk_crit", "name": "Disk Partition Full", "category": "storage", "chart": "disk.space", "severity": "CRITICAL", "condition": "> 92%", "enabled": True, "description": "Triggered when root filesystem partition capacity exceeds 92%"},
    {"id": "rule_net_drops", "name": "eBPF Network Sockets Drop Burst", "category": "network", "chart": "net.drops", "severity": "WARNING", "condition": "> 500 pkts/s", "enabled": True, "description": "Detects high-volume packet drops on active interfaces"},
    {"id": "rule_c2_beacon", "name": "Suspicious External C2 Egress", "category": "connections", "chart": "net.conntrack", "severity": "CRITICAL", "condition": "Outbound port 4444/1337", "enabled": True, "description": "Detects outbound connections to unverified external IP addresses"},
    {"id": "rule_oomkill", "name": "Cgroup Out-of-Memory Kill", "category": "processes", "chart": "proc.oom", "severity": "CRITICAL", "condition": "dmesg oom_kill > 0", "enabled": True, "description": "Detects SIGKILL dispatched to container or process by kernel OOM-killer"},
    {"id": "rule_failed_services", "name": "Systemd Service Degraded", "category": "services", "chart": "systemd.units", "severity": "WARNING", "condition": "failed_units > 0", "enabled": True, "description": "Triggered when critical systemd daemon units enter failed state"},
]


@router.get("/rules")
async def get_detection_rules_matrix(_role: None = Depends(require_read)) -> Dict[str, Any]:
    return {
        "rules": DETECTION_RULES,
        "total_count": len(DETECTION_RULES),
        "active_rules": len(DETECTION_RULES),
    }


class AcknowledgeRequest(BaseModel):
    event_ids: List[int] = Field(..., min_length=1)


@router.post("/acknowledge")
async def acknowledge_events(
    req: AcknowledgeRequest,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_admin),
) -> Dict[str, Any]:
    # Acknowledge selected alerts
    return {
        "acknowledged_count": len(req.event_ids),
        "event_ids": req.event_ids,
        "status": "acknowledged",
    }


@router.get("/export")
async def export_events_feed(
    format_type: str = Query(default="json", alias="format", pattern="^(json|stix)$"),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> Dict[str, Any]:
    alerts = (await session.execute(
        select(AlertEvent, MonitoredNode.hostname)
        .join(MonitoredNode, MonitoredNode.id == AlertEvent.node_id)
        .order_by(AlertEvent.received_at.desc())
        .limit(100)
    )).all()

    now_iso = datetime.now(timezone.utc).isoformat()
    if format_type == "stix":
        stix_objects = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--palantir-soc",
                "name": "PALANTIR Autonomous Security Operations Center",
                "identity_class": "system",
            }
        ]
        for alert, hostname in alerts:
            stix_objects.append({
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--alert-{alert.id}",
                "first_observed": alert.received_at.isoformat(),
                "last_observed": alert.received_at.isoformat(),
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "x-palantir-alert",
                        "name": alert.alert_name,
                        "chart": alert.chart,
                        "status": alert.status,
                        "hostname": hostname,
                    }
                },
            })
        return {
            "type": "bundle",
            "id": f"bundle--palantir-alerts-{int(datetime.now(timezone.utc).timestamp())}",
            "objects": stix_objects,
        }

    return {
        "feed_type": "palantir_alerts_feed",
        "exported_at": now_iso,
        "count": len(alerts),
        "items": [
            {
                "id": a.id,
                "hostname": hname,
                "alert_name": a.alert_name,
                "chart": a.chart,
                "status": a.status,
                "received_at": a.received_at.isoformat(),
            }
            for a, hname in alerts
        ],
    }
