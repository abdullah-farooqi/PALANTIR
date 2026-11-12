import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sqlalchemy import delete, select
from workers.celery_app import celery_app
from core.database import get_sync_session
from models.metric import MetricSnapshot
from models.log_event import LogEvent
from models.investigation_evidence import InvestigationEvidence
from core.config import settings

logger = logging.getLogger(__name__)


def _evidence_file(root: Path, storage_key: str | None) -> Path | None:
    if not storage_key:
        return None
    try:
        resolved_root = root.resolve()
        resolved_file = (resolved_root / storage_key).resolve()
        resolved_file.relative_to(resolved_root)
        return resolved_file
    except (OSError, ValueError):
        return None


def _prune_pcap_evidence(session, now: datetime) -> tuple[int, int]:
    """Remove expired/over-quota PCAP blobs and leave an explanatory evidence row."""
    root = settings.PCAP_STORAGE_DIR
    if not root.exists():
        return 0, 0
    rows = session.execute(
        select(InvestigationEvidence)
        .where(
            InvestigationEvidence.status == "complete",
            InvestigationEvidence.storage_key.is_not(None),
        )
        .order_by(InvestigationEvidence.uploaded_at.asc(), InvestigationEvidence.id.asc())
    ).scalars().all()
    cutoff = now - timedelta(days=settings.PCAP_EVIDENCE_RETENTION_DAYS)
    limit_bytes = settings.PCAP_EVIDENCE_STORAGE_LIMIT_GB * 1024**3
    sizes: dict[int, int] = {}
    total = 0
    for row in rows:
        path = _evidence_file(root, row.storage_key)
        size = path.stat().st_size if path and path.is_file() else 0
        sizes[row.id] = size
        total += size

    evicted: dict[int, str] = {}
    for row in rows:
        if row.uploaded_at and row.uploaded_at < cutoff:
            evicted[row.id] = "PCAP evidence expired under the configured retention period."
            total -= sizes[row.id]
    for row in rows:
        if total <= limit_bytes:
            break
        if row.id in evicted:
            continue
        evicted[row.id] = "PCAP evidence was removed to stay within the configured storage limit."
        total -= sizes[row.id]

    removed = 0
    referenced: set[Path] = set()
    for row in rows:
        path = _evidence_file(root, row.storage_key)
        if row.id in evicted:
            if path:
                try:
                    path.unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    logger.warning("Could not remove expired PCAP evidence %s", row.id, exc_info=True)
                    continue
            row.storage_key = None
            row.status = "unavailable"
            row.error_message = evicted[row.id]
        elif path:
            referenced.add(path)

    # Recover disk space after interrupted transfers or evidence rows deleted by cascade.
    orphan_cutoff = now - timedelta(days=1)
    orphaned = 0
    for path in root.rglob("*"):
        if not path.is_file() or path in referenced:
            continue
        try:
            if path.stat().st_mtime < orphan_cutoff.timestamp():
                path.unlink()
                orphaned += 1
        except OSError:
            logger.warning("Could not remove orphaned PCAP storage file %s", path, exc_info=True)
    return removed, orphaned


@celery_app.task(bind=True)
def prune_old_snapshots(self):
    """Prune metric snapshots and structured host logs using configured retention."""
    now = datetime.now(timezone.utc)
    metric_cutoff = now - timedelta(hours=settings.METRICS_RETENTION_HOURS)
    log_cutoff = now - timedelta(days=settings.LOG_RETENTION_DAYS)
    with get_sync_session() as session:
        try:
            result = session.execute(delete(MetricSnapshot).where(MetricSnapshot.collected_at < metric_cutoff))
            log_result = session.execute(delete(LogEvent).where(LogEvent.event_at < log_cutoff))
            pcap_removed, pcap_orphaned = _prune_pcap_evidence(session, now)
            session.commit()
            logger.info(
                "Pruned %s metric snapshots, %s log events, %s expired PCAP files, and %s orphaned PCAP files (metric cutoff %s, log cutoff %s).",
                result.rowcount,
                log_result.rowcount,
                pcap_removed,
                pcap_orphaned,
                metric_cutoff,
                log_cutoff,
            )
        except Exception as exc:
            logger.error(f"Failed to prune old snapshots: {exc}")
            session.rollback()
