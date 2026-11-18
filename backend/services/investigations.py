import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from core.config import settings
from integrations.agent.client import AgentCollectorClient
from integrations.agent.pcap_contract import validate_pcap_snapshot
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


async def _record_pcap_snapshot(
    session,
    *,
    node_id: int,
    investigation_id: int,
    trigger_type: str,
    snapshot: Any,
    client: AgentCollectorClient,
    alert_event_id: int | None = None,
) -> int:
    """Validate and persist a complete manifest before scheduling any file transfer."""
    raw_snapshot_id = snapshot.get("snapshot_id") if isinstance(snapshot, dict) else None
    valid_snapshot_id = (
        raw_snapshot_id
        if isinstance(raw_snapshot_id, str) and len(raw_snapshot_id) == 32
        and all(char in "0123456789abcdef" for char in raw_snapshot_id)
        else None
    )
    try:
        manifest = validate_pcap_snapshot(snapshot, trigger_type)
    except Exception:
        logger.warning("Collector returned an invalid PCAP snapshot manifest for investigation %s", investigation_id, exc_info=True)
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=alert_event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            capture_snapshot_id=valid_snapshot_id,
            capture_trigger_type=trigger_type,
            captured_at=datetime.now(timezone.utc),
            status="failed",
            error_message="Collector returned an invalid PCAP snapshot manifest.",
        ))
        await _maybe_await(session.commit())
        if valid_snapshot_id:
            try:
                await client.release_pcap_snapshot(valid_snapshot_id)
            except Exception:
                logger.warning("Could not release invalid PCAP snapshot %s", valid_snapshot_id, exc_info=True)
        return 0

    snapshot_id = manifest.snapshot_id
    if not manifest.files:
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=alert_event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            capture_snapshot_id=snapshot_id,
            capture_snapshot_created_at=manifest.created_at,
            capture_trigger_type=trigger_type,
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
    for item in manifest.files:
        existing = (await _execute(session, select(InvestigationEvidence).where(
            InvestigationEvidence.investigation_id == investigation_id,
            InvestigationEvidence.collector_file_id == item.file_id,
        ))).scalar_one_or_none()
        if existing is not None:
            continue
        filename = item.filename or item.file_id + {
            "none": "", "gzip": ".gz", "zstd": ".zst",
        }[item.compression]
        evidence = InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=alert_event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            capture_snapshot_id=snapshot_id,
            capture_snapshot_created_at=manifest.created_at,
            capture_trigger_type=trigger_type,
            collector_file_id=item.file_id,
            file_name=filename[:512],
            collector_size_bytes=item.size_bytes,
            original_size_bytes=item.original_size_bytes,
            capture_interface=item.interface,
            snaplen=item.snaplen,
            packet_count=item.packet_count,
            capture_started_at=item.capture_started_at,
            capture_finished_at=item.capture_finished_at,
            duration_seconds=item.duration_seconds,
            captured_at=datetime.now(timezone.utc),
            compression=item.compression,
            collector_sha256=item.sha256,
            hash_status=item.hash_status,
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


async def request_pcap_evidence_for_investigation(
    session,
    *,
    node_id: int,
    investigation_id: int,
    trigger_type: str = "manual",
    alert_event_id: int | None = None,
) -> int:
    """Take a collector snapshot, retain its validated manifest, and queue transfers."""
    node = (await _execute(session, select(MonitoredNode).where(MonitoredNode.id == node_id))).scalar_one_or_none()
    if node is None or not node.collector_url:
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=alert_event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            capture_trigger_type=trigger_type,
            captured_at=datetime.now(timezone.utc),
            status="unavailable",
            error_message="The affected node has no active collector URL.",
        ))
        await _maybe_await(session.commit())
        return 0

    client = AgentCollectorClient(node.collector_url, timeout=min(settings.PCAP_TRANSFER_TIMEOUT_SECONDS, 30.0))
    try:
        snapshot = await client.create_pcap_snapshot(trigger_type=trigger_type)
    except Exception as exc:
        logger.warning("Could not snapshot PCAP evidence for investigation %s: %s", investigation_id, exc)
        session.add(InvestigationEvidence(
            investigation_id=investigation_id,
            alert_event_id=alert_event_id,
            node_id=node_id,
            evidence_type="pcap_collection",
            capture_trigger_type=trigger_type,
            captured_at=datetime.now(timezone.utc),
            status="failed",
            error_message=f"Collector snapshot failed: {str(exc)[:400]}",
        ))
        await _maybe_await(session.commit())
        return 0
    return await _record_pcap_snapshot(
        session,
        node_id=node_id,
        investigation_id=investigation_id,
        trigger_type=trigger_type,
        snapshot=snapshot,
        client=client,
        alert_event_id=alert_event_id,
    )


async def request_pcap_evidence_for_alert(
    session,
    event_id: int,
    node_id: int,
    investigation_id: int,
) -> int:
    """Pin an alert capture unless the event is outside severity or cooldown policy."""
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
                capture_trigger_type="alert",
                captured_at=datetime.now(timezone.utc),
                status="unavailable",
                error_message="Capture skipped by the per-alert cooldown; this alert repeated within the active episode.",
            ))
            await _maybe_await(session.commit())
            return 0

    return await request_pcap_evidence_for_investigation(
        session,
        node_id=node_id,
        investigation_id=investigation_id,
        trigger_type="alert",
        alert_event_id=event_id,
    )
