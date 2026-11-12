import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from core.config import settings
from integrations.agent.client import AgentCollectorClient
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.investigation import AgentInvestigation
from models.investigation_evidence import InvestigationEvidence
from models.node import MonitoredNode

logger = logging.getLogger(__name__)


async def _maybe_await(value):
    return await value if hasattr(value, "__await__") else value


async def _execute(session, statement):
    return await _maybe_await(session.execute(statement))


def _enqueue(investigation_id: int, job_id: str) -> None:
    # Import locally to avoid a Celery task/service import cycle.
    from workers.investigation_tasks import run_investigation

    run_investigation.apply_async(args=[investigation_id], task_id=job_id)


async def enqueue_investigation_async(
    session,
    *,
    node_id: int,
    trigger_type: str,
    trigger_id: int | None,
) -> tuple[AgentInvestigation, bool]:
    now = datetime.now(timezone.utc)
    job_id = str(uuid4())
    investigation = AgentInvestigation(
        node_id=node_id,
        job_id=job_id,
        queued_at=now,
        trigger_type=trigger_type,
        trigger_id=trigger_id,
        status="queued",
        progress=0,
    )
    session.add(investigation)
    await _maybe_await(session.flush())
    await _maybe_await(session.commit())
    try:
        _enqueue(investigation.id, job_id)
    except Exception:
        await _maybe_await(session.rollback())
        stored = (await _execute(session,
            select(AgentInvestigation).where(AgentInvestigation.id == investigation.id)
        )).scalar_one_or_none()
        if stored is None:
            raise
        stored.status = "failed"
        stored.completed_at = datetime.now(timezone.utc)
        stored.error_code = "dispatch_failed"
        stored.error_message = "The investigation could not be submitted to the worker queue."
        stored.summary = stored.error_message
        await _maybe_await(session.commit())
        return stored, False

    linked = False
    if trigger_type == "alert" and trigger_id is not None:
        event = (await _execute(session, select(AlertEvent).where(
            AlertEvent.id == trigger_id, AlertEvent.node_id == node_id
        ))).scalar_one_or_none()
        if event is not None:
            event.investigation_id = investigation.id
            linked = True
    elif trigger_type == "anomaly" and trigger_id is not None:
        event = (await _execute(session, select(AnomalyEvent).where(
            AnomalyEvent.id == trigger_id, AnomalyEvent.node_id == node_id
        ))).scalar_one_or_none()
        if event is not None:
            event.investigation_id = investigation.id
            linked = True
    try:
        if linked:
            await _maybe_await(session.commit())
        await _maybe_await(session.refresh(investigation))
    except Exception:
        await _maybe_await(session.rollback())
        logger.exception("Investigation %s was queued but its event link could not be saved", investigation.id)
    return investigation, True


def _parse_capture_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


async def _enqueue_pcap_transfer(evidence_id: int) -> bool:
    try:
        from workers.pcap_tasks import transfer_pcap_artifact

        transfer_pcap_artifact.apply_async(
            args=[evidence_id],
            task_id=f"pcap-evidence-{evidence_id}",
        )
        return True
    except Exception:
        logger.exception("Could not enqueue PCAP evidence transfer %s", evidence_id)
        return False


async def request_pcap_evidence_for_alert(
    session,
    event_id: int,
    node_id: int,
    investigation_id: int,
) -> int:
    """Pin the collector's current ring for an alert, then queue file transfers.

    Snapshot creation only closes the current capture segment and returns metadata;
    potentially large transfers happen in Celery. Failures are recorded against the
    investigation and do not change the alert webhook result.
    """
    event = (await _execute(session, select(AlertEvent).where(
        AlertEvent.id == event_id,
        AlertEvent.node_id == node_id,
    ))).scalar_one_or_none()
    if event is None or event.status not in {"WARNING", "CRITICAL"}:
        return 0

    if settings.PCAP_ALERT_COOLDOWN_SECONDS > 0:
        previous = (await _execute(session, select(AlertEvent).where(
            AlertEvent.node_id == node_id,
            AlertEvent.alert_name == event.alert_name,
            AlertEvent.chart == event.chart,
            AlertEvent.id < event.id,
        ).order_by(AlertEvent.received_at.desc(), AlertEvent.id.desc()).limit(1))).scalar_one_or_none()
        if (
            previous is not None
            and previous.status == event.status
            and previous.received_at is not None
            and event.received_at is not None
            and event.received_at - previous.received_at < timedelta(seconds=settings.PCAP_ALERT_COOLDOWN_SECONDS)
        ):
            session.add(InvestigationEvidence(
                investigation_id=investigation_id,
                alert_event_id=event_id,
                node_id=node_id,
                evidence_type="pcap_collection",
                captured_at=datetime.now(timezone.utc),
                status="unavailable",
                error_message="Capture skipped by the per-alert cooldown; this alert repeated within the active episode.",
            ))
            await _maybe_await(session.commit())
            return 0

    node = (await _execute(session, select(MonitoredNode).where(MonitoredNode.id == node_id))).scalar_one_or_none()
    if node is None or not node.collector_url:
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            captured_at=datetime.now(timezone.utc),
            status="unavailable",
            error_message="The affected node has no active collector URL.",
        ))
        await _maybe_await(session.commit())
        return 0

    client = AgentCollectorClient(node.collector_url, timeout=min(settings.PCAP_TRANSFER_TIMEOUT_SECONDS, 30.0))
    try:
        snapshot = await client.create_pcap_snapshot()
    except Exception as exc:
        logger.warning("Could not snapshot PCAP evidence for alert %s: %s", event_id, exc)
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            captured_at=datetime.now(timezone.utc),
            status="failed",
            error_message=f"Collector snapshot failed: {str(exc)[:400]}",
        ))
        await _maybe_await(session.commit())
        return 0

    snapshot_id = snapshot.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not re.fullmatch(r"[0-9a-f]{32}", snapshot_id):
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            captured_at=datetime.now(timezone.utc),
            status="failed",
            error_message="Collector returned an invalid PCAP snapshot manifest.",
        ))
        await _maybe_await(session.commit())
        return 0

    files = snapshot.get("files") if isinstance(snapshot.get("files"), list) else []
    if not files:
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            capture_snapshot_id=snapshot_id,
            captured_at=datetime.now(timezone.utc),
            status="unavailable",
            error_message="The collector snapshot contained no finalized PCAP files.",
        ))
        await _maybe_await(session.commit())
        try:
            await client.release_pcap_snapshot(snapshot_id)
        except Exception:
            logger.warning("Could not release empty PCAP snapshot %s", snapshot_id, exc_info=True)
        return 0

    evidence_rows: list[InvestigationEvidence] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        file_id = item.get("file_id")
        if not isinstance(file_id, str) or not re.fullmatch(r"capture_\d{8}T\d{6}Z_[0-9a-f]{12}\.pcap\d*", file_id):
            continue
        existing = (await _execute(session, select(InvestigationEvidence).where(
            InvestigationEvidence.investigation_id == investigation_id,
            InvestigationEvidence.collector_file_id == file_id,
        ))).scalar_one_or_none()
        if existing is not None:
            continue
        filename = item.get("filename")
        filename = filename.rsplit("/", 1)[-1] if isinstance(filename, str) else file_id
        evidence = InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            capture_snapshot_id=snapshot_id,
            collector_file_id=file_id,
            file_name=filename[:512],
            size_bytes=item.get("size_bytes") if isinstance(item.get("size_bytes"), int) else None,
            original_size_bytes=item.get("original_size_bytes") if isinstance(item.get("original_size_bytes"), int) else None,
            capture_started_at=_parse_capture_time(item.get("capture_started_at")),
            capture_finished_at=_parse_capture_time(item.get("capture_finished_at")),
            duration_seconds=item.get("duration_seconds") if isinstance(item.get("duration_seconds"), int) else None,
            captured_at=datetime.now(timezone.utc),
            compression=str(item.get("compression") or "none")[:16],
            status="queued",
        )
        session.add(evidence)
        evidence_rows.append(evidence)

    if not evidence_rows:
        try:
            await client.release_pcap_snapshot(snapshot_id)
        except Exception:
            logger.warning("Could not release duplicate PCAP snapshot %s", snapshot_id, exc_info=True)
        return 0

    await _maybe_await(session.flush())
    evidence_ids = [row.id for row in evidence_rows]
    await _maybe_await(session.commit())

    queued = 0
    for evidence_id in evidence_ids:
        if await _enqueue_pcap_transfer(evidence_id):
            queued += 1
            continue
        row = (await _execute(session, select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id))).scalar_one_or_none()
        if row is not None:
            row.status = "failed"
            row.error_message = "PCAP transfer could not be submitted to the worker queue."
    await _maybe_await(session.commit())
    if queued == 0:
        try:
            await client.release_pcap_snapshot(snapshot_id)
        except Exception:
            logger.warning("Could not release unqueued PCAP snapshot %s", snapshot_id, exc_info=True)
    return queued
