"""Retryable collector-to-master PCAP transfer jobs."""

import asyncio
import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, select, text

from core.config import settings
from core.database import get_sync_session
from integrations.agent.client import AgentCollectorClient
from models.investigation_evidence import InvestigationEvidence
from models.node import MonitoredNode
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)
_UPLOAD_LEASE = timedelta(minutes=10)
_PCAP_STORAGE_LOCK = 739104221


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mark_failed(evidence_id: int, message: str, *, retrying: bool) -> None:
    with get_sync_session() as session:
        row = session.execute(
            select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id)
        ).scalar_one_or_none()
        if row is None:
            return
        row.status = "queued" if retrying else "failed"
        row.upload_started_at = None
        row.error_message = message[:1000]
        session.commit()


def _release_snapshot_if_done(snapshot_id: str | None, node_id: int) -> None:
    if not snapshot_id:
        return
    try:
        with get_sync_session() as session:
            pending = session.execute(
                select(func.count(InvestigationEvidence.id)).where(
                    InvestigationEvidence.capture_snapshot_id == snapshot_id,
                    InvestigationEvidence.status.in_(("queued", "uploading")),
                )
            ).scalar_one()
            node = session.execute(
                select(MonitoredNode).where(MonitoredNode.id == node_id)
            ).scalar_one_or_none()
            collector_url = node.collector_url if node else None
    except Exception:
        logger.warning("Could not check remaining PCAP transfers for snapshot %s", snapshot_id, exc_info=True)
        return
    if pending or not collector_url:
        return
    try:
        asyncio.run(AgentCollectorClient(collector_url).release_pcap_snapshot(snapshot_id))
    except Exception:
        logger.warning("Could not release transferred PCAP snapshot %s", snapshot_id, exc_info=True)


@celery_app.task(
    bind=True,
    name="workers.pcap_tasks.transfer_pcap_artifact",
    max_retries=4,
    default_retry_delay=20,
)
def transfer_pcap_artifact(self, evidence_id: int):
    """Stream one collector artifact to durable master storage and record its hash."""
    quota_rejected = False
    rejected_snapshot_id = None
    rejected_node_id = None
    with get_sync_session() as session:
        row = session.execute(
            select(InvestigationEvidence)
            .where(InvestigationEvidence.id == evidence_id)
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            return {"status": "missing", "evidence_id": evidence_id}
        if row.status == "complete":
            return {"status": "complete", "evidence_id": evidence_id}
        now = datetime.now(timezone.utc)
        if (
            row.status == "uploading"
            and row.upload_started_at is not None
            and row.upload_started_at > now - _UPLOAD_LEASE
        ):
            return {"status": "already_uploading", "evidence_id": evidence_id}
        node = session.execute(
            select(MonitoredNode).where(MonitoredNode.id == row.node_id)
        ).scalar_one_or_none()
        if node is None or not node.collector_url or not row.collector_file_id:
            row.status = "failed"
            row.error_message = "Collector or source file reference is unavailable."
            session.commit()
            return {"status": "failed", "evidence_id": evidence_id}
        node_id = row.node_id
        investigation_id = row.investigation_id
        collector_url = node.collector_url
        file_id = row.collector_file_id
        snapshot_id = row.capture_snapshot_id
        rejected_snapshot_id = snapshot_id
        rejected_node_id = node_id
        # Reserve estimated bytes under a transaction advisory lock so concurrent
        # workers cannot all pass the same storage quota check.
        session.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": _PCAP_STORAGE_LOCK})
        used_bytes = session.execute(
            select(func.coalesce(func.sum(InvestigationEvidence.size_bytes), 0)).where(
                InvestigationEvidence.status.in_(("complete", "uploading"))
            )
        ).scalar_one()
        if row.status == "uploading":
            used_bytes -= row.size_bytes or 0
        reserve_bytes = row.size_bytes or settings.PCAP_MAX_UPLOAD_MB * 1024 * 1024
        storage_limit = settings.PCAP_EVIDENCE_STORAGE_LIMIT_GB * 1024**3
        if used_bytes + reserve_bytes > storage_limit:
            row.status = "failed"
            row.error_message = "PCAP transfer was rejected because the configured evidence storage limit is full."
            row.upload_started_at = None
            quota_rejected = True
            session.commit()
        if quota_rejected:
            pass
        else:
            row.status = "uploading"
            row.upload_started_at = now
            row.error_message = None
            session.commit()

    if quota_rejected:
        _release_snapshot_if_done(rejected_snapshot_id, rejected_node_id)
        return {"status": "failed", "evidence_id": evidence_id, "reason": "storage_limit"}

    directory = settings.PCAP_STORAGE_DIR / str(node_id) / str(investigation_id)
    partial = directory / f"evidence-{evidence_id}.partial"
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        transfer = asyncio.run(
            AgentCollectorClient(collector_url).download_pcap_file(
                file_id,
                partial,
                max_bytes=settings.PCAP_MAX_UPLOAD_MB * 1024 * 1024,
                timeout=settings.PCAP_TRANSFER_TIMEOUT_SECONDS,
            )
        )
        if transfer["size_bytes"] <= 0:
            raise RuntimeError("Collector returned an empty PCAP artifact")
        content_types = {
            "application/zstd": ("zst", ".pcap.zst"),
            "application/gzip": ("gz", ".pcap.gz"),
            "application/vnd.tcpdump.pcap": ("none", ".pcap"),
        }
        actual_format = content_types.get(transfer["content_type"])
        if actual_format is None:
            raise RuntimeError(f"Collector returned an unsupported PCAP content type: {transfer['content_type']}")
        compression, suffix = actual_format
        destination = directory / f"evidence-{evidence_id}{suffix}"
        digest = _sha256(partial)
        os.replace(partial, destination)
        storage_key = destination.relative_to(settings.PCAP_STORAGE_DIR).as_posix()
        with get_sync_session() as session:
            row = session.execute(
                select(InvestigationEvidence).where(InvestigationEvidence.id == evidence_id)
            ).scalar_one_or_none()
            if row is None:
                destination.unlink(missing_ok=True)
                return {"status": "deleted", "evidence_id": evidence_id}
            row.storage_key = storage_key
            row.size_bytes = transfer["size_bytes"]
            row.sha256 = digest
            row.compression = compression
            source_name = Path(file_id).name
            row.file_name = source_name + (".zst" if compression == "zst" else ".gz" if compression == "gz" else "")
            row.status = "complete"
            row.uploaded_at = datetime.now(timezone.utc)
            row.upload_started_at = None
            row.error_message = None
            session.commit()
        _release_snapshot_if_done(snapshot_id, node_id)
        return {"status": "complete", "evidence_id": evidence_id, "size_bytes": transfer["size_bytes"]}
    except Exception as exc:
        partial.unlink(missing_ok=True)
        retrying = self.request.retries < self.max_retries
        _mark_failed(evidence_id, str(exc), retrying=retrying)
        if not retrying:
            _release_snapshot_if_done(snapshot_id, node_id)
        logger.warning(
            "PCAP transfer %s failed (attempt %s/%s): %s",
            evidence_id,
            self.request.retries + 1,
            self.max_retries + 1,
            exc,
        )
        if retrying:
            raise self.retry(exc=exc, countdown=min(120, 15 * (self.request.retries + 1)))
        raise
