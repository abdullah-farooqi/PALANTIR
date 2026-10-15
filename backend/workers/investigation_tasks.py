import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from core.config import settings
from core.database import get_sync_session
from core.investigation_contracts import InvestigationEvidenceResult
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.investigation import AgentInvestigation
from models.metric import MetricSnapshot
from models.node import MonitoredNode
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _set_progress(session, investigation_id: int, progress: int) -> AgentInvestigation:
    row = session.execute(
        select(AgentInvestigation)
        .where(AgentInvestigation.id == investigation_id)
        .with_for_update()
    ).scalar_one()
    row.progress = progress
    session.commit()
    return row


def _evidence(session, investigation: AgentInvestigation, node: MonitoredNode, now: datetime) -> dict:
    since = now - timedelta(hours=min(settings.METRICS_RETENTION_HOURS, 24))
    source = func.coalesce(MetricSnapshot.data["source"].as_string(), "palantir-agent")
    metric_rows = session.execute(
        select(
            MetricSnapshot.category,
            source.label("source"),
            MetricSnapshot.collected_at,
            MetricSnapshot.cpu_pct,
            MetricSnapshot.ram_used_mb,
            MetricSnapshot.ram_total_mb,
            MetricSnapshot.load_avg,
            MetricSnapshot.swap_used_mb,
            MetricSnapshot.data,
        )
        .where(
            MetricSnapshot.node_id == node.id,
            MetricSnapshot.collected_at >= since,
            MetricSnapshot.data["sample"].as_string().is_(None),  # ignore per-second CPU sample rows
        )
        .order_by(MetricSnapshot.collected_at.desc(), MetricSnapshot.id.desc())
        .limit(200)
    ).all()
    newest_metrics = {}
    for row in metric_rows:
        key = (row.category, row.source)
        if key in newest_metrics:
            continue
        values = {}
        if row.category == "system":
            values = {
                name: getattr(row, name)
                for name in ("cpu_pct", "ram_used_mb", "ram_total_mb", "load_avg", "swap_used_mb")
                if getattr(row, name) is not None
            }
        else:
            raw_inner = (row.data or {}).get("data") if isinstance(row.data, dict) else {}
            if isinstance(raw_inner, dict):
                if row.category == "storage":
                    fs_list = raw_inner.get("filesystems") or []
                    io_list = raw_inner.get("disk_io") or []
                    values = {
                        "filesystems": len(fs_list),
                        "disk_devices": len(io_list),
                    }
                    if fs_list:
                        root_fs = next((f for f in fs_list if f.get("mountpoint") == "/"), fs_list[0])
                        if root_fs.get("percent") is not None:
                            values["root_used_pct"] = round(float(root_fs["percent"]), 1)
                elif row.category == "processes":
                    values = {
                        "process_count": raw_inner.get("process_count") or len(raw_inner.get("top_by_rss") or []),
                    }
                    oom = raw_inner.get("oom_counters")
                    if isinstance(oom, dict):
                        values["oom_kills"] = sum(v for v in oom.values() if isinstance(v, (int, float)))
                elif row.category == "connections":
                    values = {
                        "sockets_count": raw_inner.get("count") or len(raw_inner.get("sockets") or []),
                    }
                elif row.category == "containers":
                    containers = raw_inner.get("containers") or []
                    running = sum(1 for c in containers if (c.get("state") or c.get("status") or "").lower() in ("running", "up"))
                    values = {
                        "containers_total": len(containers),
                        "containers_running": running,
                    }
                elif row.category == "vms":
                    vms = raw_inner.get("vms") or []
                    running_vms = sum(1 for v in vms if (v.get("state") or "").lower() == "running")
                    values = {
                        "vms_total": len(vms),
                        "vms_running": running_vms,
                    }
                elif row.category == "services":
                    services = raw_inner.get("services") or []
                    active_svc = sum(1 for s in services if s.get("active") == "active")
                    failed_svc = sum(1 for s in services if s.get("active") == "failed")
                    values = {
                        "services_total": len(services),
                        "active": active_svc,
                        "failed": failed_svc,
                    }
                elif row.category == "network":
                    ifaces = raw_inner.get("interfaces") or {}
                    values = {
                        "interfaces_count": len(ifaces) if isinstance(ifaces, dict) else 0,
                    }

        newest_metrics[key] = {
            "category": row.category,
            "source": row.source,
            "collected_at": row.collected_at.isoformat(),
            "metrics": values,
        }

    # Use one ranked transition per alert identity so old uncleared alerts remain visible.
    latest_transitions = (
        select(
            AlertEvent.id.label("event_id"),
            func.row_number().over(
                partition_by=(AlertEvent.node_id, AlertEvent.alert_name, AlertEvent.chart),
                order_by=(AlertEvent.received_at.desc(), AlertEvent.id.desc()),
            ).label("transition_rank"),
        )
        .where(AlertEvent.node_id == node.id)
        .subquery()
    )
    latest_alert_rows = session.execute(
        select(AlertEvent)
        .join(latest_transitions, AlertEvent.id == latest_transitions.c.event_id)
        .where(latest_transitions.c.transition_rank == 1, AlertEvent.status.in_(("WARNING", "CRITICAL")))
        .order_by(AlertEvent.received_at.desc(), AlertEvent.id.desc())
        .limit(10)
    ).scalars().all()
    active_alerts = [
        {
            "id": event.id,
            "alert_name": event.alert_name,
            "chart": event.chart,
            "severity": event.status,
            "received_at": event.received_at.isoformat(),
        }
        for event in latest_alert_rows
    ]

    anomalies = session.execute(
        select(AnomalyEvent)
        .where(AnomalyEvent.node_id == node.id, AnomalyEvent.detected_at >= since)
        .order_by(AnomalyEvent.detected_at.desc(), AnomalyEvent.id.desc())
        .limit(10)
    ).scalars().all()
    trigger = None
    if investigation.trigger_type == "alert" and investigation.trigger_id:
        event = session.execute(select(AlertEvent).where(
            AlertEvent.id == investigation.trigger_id, AlertEvent.node_id == node.id
        )).scalar_one_or_none()
        if event:
            trigger = {"type": "alert", "id": event.id, "severity": event.status,
                       "alert_name": event.alert_name, "chart": event.chart,
                       "received_at": event.received_at.isoformat()}
    elif investigation.trigger_type == "anomaly" and investigation.trigger_id:
        event = session.execute(select(AnomalyEvent).where(
            AnomalyEvent.id == investigation.trigger_id, AnomalyEvent.node_id == node.id
        )).scalar_one_or_none()
        if event:
            trigger = {"type": "anomaly", "id": event.id, "detected_at": event.detected_at.isoformat(),
                       "contexts": event.contexts, "scores": event.scores, "max_score": event.max_score}
    else:
        trigger = {"type": "manual", "id": None}

    return {
        "schema_version": 1,
        "kind": "telemetry_evidence_summary",
        "generated_at": now.isoformat(),
        "node": {"id": node.id, "hostname": node.hostname},
        "trigger": trigger,
        "window": {"since": since.isoformat(), "until": now.isoformat()},
        "evidence": {
            "latest_metrics": list(newest_metrics.values())[:16],
            "active_alerts": active_alerts,
            "recent_anomalies": [
                {"id": event.id, "detected_at": event.detected_at.isoformat(),
                 "contexts": event.contexts, "scores": event.scores, "max_score": event.max_score}
                for event in anomalies
            ],
        },
        "assessment": {"result": "evidence_collected", "root_cause_inferred": False},
    }


@celery_app.task(bind=True, name="workers.investigation_tasks.run_investigation")
def run_investigation(self, investigation_id: int):
    with get_sync_session() as session:
        try:
            investigation = session.execute(
                select(AgentInvestigation)
                .where(AgentInvestigation.id == investigation_id)
                .with_for_update()
            ).scalar_one()
            if investigation.status in {"running", "complete", "failed", "cancelled"}:
                return {"status": investigation.status, "investigation_id": investigation.id}
            now = datetime.now(timezone.utc)
            investigation.status = "running"
            investigation.started_at = now
            investigation.progress = 5
            investigation.error_code = None
            investigation.error_message = None
            investigation.queue_delay_ms = max(
                0,
                int((now - investigation.queued_at).total_seconds() * 1000),
            ) if investigation.queued_at else None
            session.commit()

            node = session.execute(
                select(MonitoredNode).where(MonitoredNode.id == investigation.node_id)
            ).scalar_one()
            _set_progress(session, investigation.id, 35)
            result = _evidence(session, investigation, node, datetime.now(timezone.utc))
            result = InvestigationEvidenceResult.model_validate(result).model_dump(mode="json")
            _set_progress(session, investigation.id, 80)
            trigger = result["trigger"] or {"type": investigation.trigger_type}
            if trigger.get("type") == "alert":
                summary = (
                    f"Evidence summary for {trigger.get('severity')} alert "
                    f"{trigger.get('alert_name')} on {node.hostname}; "
                    f"{len(result['evidence']['latest_metrics'])} category/source metric groups, "
                    f"{len(result['evidence']['active_alerts'])} active alerts, and "
                    f"{len(result['evidence']['recent_anomalies'])} recent anomaly events were captured."
                )
            elif trigger.get("type") == "anomaly":
                summary = (
                    f"Evidence summary for anomaly on {node.hostname}; contexts: "
                    f"{', '.join(trigger.get('contexts', []))}. Captured "
                    f"{len(result['evidence']['latest_metrics'])} category/source metric groups."
                )
            else:
                summary = (
                    f"Manual telemetry evidence summary for {node.hostname}; captured "
                    f"{len(result['evidence']['latest_metrics'])} category/source metric groups, "
                    f"{len(result['evidence']['active_alerts'])} active alerts, and "
                    f"{len(result['evidence']['recent_anomalies'])} recent anomaly events. "
                    "This workflow summarizes evidence and does not infer a root cause."
                )
            investigation = session.execute(
                select(AgentInvestigation).where(AgentInvestigation.id == investigation_id)
            ).scalar_one()
            investigation.raw_output = result
            investigation.summary = summary[:2000]
            investigation.status = "complete"
            investigation.progress = 100
            investigation.completed_at = datetime.now(timezone.utc)
            session.commit()
            return {"status": "complete", "investigation_id": investigation_id}
        except Exception:
            session.rollback()
            logger.exception("Investigation job %s failed", investigation_id)
            row = session.execute(
                select(AgentInvestigation).where(AgentInvestigation.id == investigation_id)
            ).scalar_one_or_none()
            if row is not None:
                row.status = "failed"
                row.completed_at = datetime.now(timezone.utc)
                row.error_code = "execution_failed"
                row.error_message = "The investigation workflow could not collect its evidence."
                row.summary = row.error_message
                session.commit()
            raise
