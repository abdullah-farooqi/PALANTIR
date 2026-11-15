import logging
from datetime import datetime, timezone
from pathlib import Path as FilePath
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from core.config import settings
from core.api_auth import require_admin, require_read
from core.cursors import decode_cursor, encode_cursor
from urllib.parse import urlparse
from models.alert import AlertEvent
from models.anomaly import AnomalyEvent
from models.investigation import AgentInvestigation
from models.investigation_evidence import InvestigationEvidence
from models.node import MonitoredNode
from models.pcap_analysis import (
    PcapAnalysisRuns,
    PcapArtifacts,
    PcapCveMatches,
    PcapFlows,
    PcapIocs,
    PcapSeverityScores,
    TcpSessions,
)
from core.storage import get_storage_backend
from workers.pcap_pipeline import start_pcap_analysis
from services.nodes import NodeService
from services.investigations import enqueue_investigation_async

router = APIRouter(prefix="/investigations", tags=["Investigations"])
logger = logging.getLogger(__name__)


class InvestigationCreateRequest(BaseModel):
    node_id: int = Field(..., ge=1, description="Monitored node ID")
    trigger_type: str = Field(default="manual", pattern=r"^(manual|alert|anomaly)$")
    trigger_id: Optional[int] = Field(default=None, ge=1)

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def validate_trigger_reference(self):
        if self.trigger_type == "manual" and self.trigger_id is not None:
            raise ValueError("Manual investigations cannot include trigger_id")
        if self.trigger_type in {"alert", "anomaly"} and self.trigger_id is None:
            raise ValueError("Alert and anomaly investigations require trigger_id")
        return self


class InvestigationResponse(BaseModel):
    id: int
    node_id: int
    node_hostname: Optional[str] = None
    node_ip: Optional[str] = None
    job_id: Optional[str] = None
    queued_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    trigger_type: str
    trigger_id: Optional[int] = None
    status: str
    progress: int = 0
    queue_delay_ms: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    summary: Optional[str] = None
    raw_output: Optional[Any] = None


def _serialize(row: AgentInvestigation) -> dict[str, Any]:
    status_value = row.status
    summary = row.summary
    if status_value == "running" and not row.job_id:
        status_value = "failed"
    node = None
    try:
        from sqlalchemy.orm import inspect as sa_inspect
        insp = sa_inspect(row)
        if "node" in insp.dict:
            node = row.node
    except Exception:
        node = None
    hostname = node.hostname if node else None
    node_ip = None
    if node and node.collector_url:
        try:
            parsed = urlparse(node.collector_url)
            node_ip = parsed.hostname
        except Exception:
            node_ip = None
    return {
        "id": row.id,
        "node_id": row.node_id,
        "node_hostname": hostname,
        "node_ip": node_ip,
        "job_id": row.job_id,
        "queued_at": row.queued_at.isoformat() if row.queued_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "trigger_type": row.trigger_type,
        "trigger_id": row.trigger_id,
        "status": status_value,
        "progress": row.progress,
        "queue_delay_ms": row.queue_delay_ms,
        "error_code": row.error_code,
        "error_message": row.error_message,
        "summary": summary,
        "raw_output": row.raw_output,
    }


def _resolve_evidence_path(storage_key: str) -> tuple[FilePath, FilePath]:
    root = settings.PCAP_STORAGE_DIR.resolve()
    file_path = (root / storage_key).resolve()
    try:
        file_path.relative_to(root)
    except ValueError as exc:
        raise ValueError("Evidence storage reference is outside the configured storage directory") from exc
    return root, file_path


@router.get("", response_model=List[InvestigationResponse])
async def list_investigations(
    limit: int = Query(default=50, ge=1, le=500, description="Max investigations to retrieve"),
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    stmt = (
        select(AgentInvestigation)
        .options(selectinload(AgentInvestigation.node))
        .order_by(func.coalesce(AgentInvestigation.started_at, AgentInvestigation.queued_at).desc(), AgentInvestigation.id.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [_serialize(row) for row in rows]


@router.get("/search")
async def search_investigations(
    node_id: int | None = Query(default=None, ge=1),
    status_filter: str | None = Query(
        default=None,
        alias="status",
        pattern="^(queued|running|complete|failed|cancelled)$",
    ),
    trigger_type: str | None = Query(default=None, pattern="^(manual|alert|anomaly)$"),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if (since is not None and since.tzinfo is None) or (until is not None and until.tzinfo is None):
        raise HTTPException(status_code=400, detail="since and until must include a timezone")
    if since and until and since >= until:
        raise HTTPException(status_code=400, detail="since must be earlier than until")
    sort_time = func.coalesce(AgentInvestigation.started_at, AgentInvestigation.queued_at)
    try:
        position = decode_cursor(cursor, {"timestamp", "id"})
        cursor_time = datetime.fromisoformat(position["timestamp"].replace("Z", "+00:00")) if position else None
        cursor_id = int(position["id"]) if position else None
        if position and (cursor_time.tzinfo is None or cursor_id <= 0):
            raise ValueError("Cursor is invalid")
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "Cursor is invalid") from exc

    statement = select(AgentInvestigation).options(selectinload(AgentInvestigation.node))
    if node_id is not None:
        statement = statement.where(AgentInvestigation.node_id == node_id)
    if status_filter is not None:
        statement = statement.where(AgentInvestigation.status == status_filter)
    if trigger_type is not None:
        statement = statement.where(AgentInvestigation.trigger_type == trigger_type)
    if since is not None:
        statement = statement.where(sort_time >= since.astimezone(timezone.utc))
    if until is not None:
        statement = statement.where(sort_time < until.astimezone(timezone.utc))
    if cursor_time is not None:
        statement = statement.where(or_(
            sort_time < cursor_time,
            and_(sort_time == cursor_time, AgentInvestigation.id < cursor_id),
        ))
    statement = statement.order_by(sort_time.desc(), AgentInvestigation.id.desc()).limit(limit + 1)
    rows = (await session.execute(statement)).scalars().all()
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = encode_cursor({
            "timestamp": (last.started_at or last.queued_at).isoformat(),
            "id": last.id,
        })
    return {
        "schema_version": 1,
        "filters": {"node_id": node_id, "status": status_filter, "trigger_type": trigger_type,
                    "since": since.isoformat() if since else None,
                    "until": until.isoformat() if until else None},
        "items": [_serialize(row) for row in page],
        "has_more": has_more,
        "next_cursor": next_cursor,
    }


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: int = Path(..., ge=1, description="Investigation ID"),
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    stmt = select(AgentInvestigation).options(selectinload(AgentInvestigation.node)).where(AgentInvestigation.id == investigation_id)
    inv = (await session.execute(stmt)).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    return _serialize(inv)


@router.get("/{investigation_id}/evidence")
async def list_investigation_evidence(
    investigation_id: int = Path(..., ge=1),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> dict[str, Any]:
    investigation = (await session.execute(
        select(AgentInvestigation.id).where(AgentInvestigation.id == investigation_id)
    )).scalar_one_or_none()
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    rows = (await session.execute(
        select(InvestigationEvidence)
        .where(InvestigationEvidence.investigation_id == investigation_id)
        .order_by(InvestigationEvidence.captured_at.desc(), InvestigationEvidence.id.desc())
    )).scalars().all()
    items = []
    for row in rows:
        items.append({
            "file_id": row.id,
            "evidence_type": row.evidence_type,
            "filename": row.file_name,
            "size_bytes": row.size_bytes,
            "original_size_bytes": row.original_size_bytes,
            "duration_seconds": row.duration_seconds,
            "capture_started_at": row.capture_started_at.isoformat() if row.capture_started_at else None,
            "capture_finished_at": row.capture_finished_at.isoformat() if row.capture_finished_at else None,
            "captured_at": row.captured_at.isoformat() if row.captured_at else None,
            "uploaded_at": row.uploaded_at.isoformat() if row.uploaded_at else None,
            "compression": row.compression,
            "sha256": row.sha256,
            "status": row.status,
            "error_message": row.error_message,
        })
    return {"schema_version": 1, "investigation_id": investigation_id, "items": items}


@router.get("/{investigation_id}/evidence/{file_id}/download")
async def download_pcap_evidence(
    investigation_id: int = Path(..., ge=1),
    file_id: int = Path(..., ge=1),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> FileResponse:
    row = (await session.execute(
        select(InvestigationEvidence).where(
            InvestigationEvidence.id == file_id,
            InvestigationEvidence.investigation_id == investigation_id,
        )
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file not found")
    if row.status != "complete" or not row.storage_key:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Evidence file is not ready for download")

    try:
        _root, file_path = _resolve_evidence_path(row.storage_key)
    except ValueError as exc:
        logger.error("Evidence %s has an invalid storage key", row.id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Evidence storage reference is invalid") from exc
    if not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored evidence file is missing")
    download_name = FilePath(row.file_name or file_path.name).name
    media_type = "application/zstd" if file_path.suffix == ".zst" else (
        "application/gzip" if file_path.suffix == ".gz" else "application/vnd.tcpdump.pcap"
    )
    return FileResponse(
        file_path,
        media_type=media_type,
        filename=download_name,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@router.get("/{investigation_id}/analysis")
async def list_investigation_analysis_runs(
    investigation_id: int = Path(..., ge=1),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> dict[str, Any]:
    inv = (await session.execute(
        select(AgentInvestigation.id).where(AgentInvestigation.id == investigation_id)
    )).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    runs = (await session.execute(
        select(PcapAnalysisRuns)
        .where(PcapAnalysisRuns.investigation_id == investigation_id)
        .order_by(PcapAnalysisRuns.started_at.desc(), PcapAnalysisRuns.id.desc())
    )).scalars().all()

    items = []
    for r in runs:
        score_row = (await session.execute(
            select(PcapSeverityScores).where(PcapSeverityScores.run_id == r.run_id)
        )).scalar_one_or_none()

        flow_count = (await session.execute(
            select(func.count(PcapFlows.id)).where(PcapFlows.run_id == r.run_id)
        )).scalar() or 0
        session_count = (await session.execute(
            select(func.count(TcpSessions.id)).where(TcpSessions.run_id == r.run_id)
        )).scalar() or 0
        artifact_count = (await session.execute(
            select(func.count(PcapArtifacts.id)).where(PcapArtifacts.run_id == r.run_id)
        )).scalar() or 0
        ioc_count = (await session.execute(
            select(func.count(PcapIocs.id)).where(PcapIocs.run_id == r.run_id)
        )).scalar() or 0
        cve_count = (await session.execute(
            select(func.count(PcapCveMatches.id)).where(PcapCveMatches.run_id == r.run_id)
        )).scalar() or 0

        items.append({
            "run_id": r.run_id,
            "evidence_id": r.evidence_id,
            "status": r.status,
            "current_step": r.current_step,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "error_step": r.error_step,
            "error_message": r.error_message,
            "rollback_started_at": r.rollback_started_at.isoformat() if r.rollback_started_at else None,
            "rollback_completed_at": r.rollback_completed_at.isoformat() if r.rollback_completed_at else None,
            "flow_count": flow_count,
            "session_count": session_count,
            "artifact_count": artifact_count,
            "ioc_count": ioc_count,
            "cve_match_count": cve_count,
            "severity_score": {
                "overall_score": float(score_row.overall_score),
                "overall_severity": score_row.overall_severity,
                "cvss_base_max": float(score_row.cvss_base_max or 0.0),
                "ioc_risk_score": float(score_row.ioc_risk_score or 0.0),
                "anomaly_score": float(score_row.anomaly_score or 0.0),
            } if score_row else None,
        })

    return {
        "schema_version": 1,
        "investigation_id": investigation_id,
        "total_runs": len(items),
        "items": items,
    }


@router.get("/{investigation_id}/analysis/{run_id}")
async def get_investigation_analysis_detail(
    investigation_id: int = Path(..., ge=1),
    run_id: str = Path(..., min_length=1),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> dict[str, Any]:
    run = (await session.execute(
        select(PcapAnalysisRuns).where(
            PcapAnalysisRuns.run_id == run_id,
            PcapAnalysisRuns.investigation_id == investigation_id,
        )
    )).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")

    score_row = (await session.execute(
        select(PcapSeverityScores).where(PcapSeverityScores.run_id == run_id)
    )).scalar_one_or_none()

    flows = (await session.execute(
        select(PcapFlows).where(PcapFlows.run_id == run_id).limit(100)
    )).scalars().all()

    tcp_sessions = (await session.execute(
        select(TcpSessions).where(TcpSessions.run_id == run_id).limit(100)
    )).scalars().all()

    artifacts = (await session.execute(
        select(PcapArtifacts).where(PcapArtifacts.run_id == run_id).limit(100)
    )).scalars().all()

    iocs = (await session.execute(
        select(PcapIocs).where(PcapIocs.run_id == run_id).limit(100)
    )).scalars().all()

    cves = (await session.execute(
        select(PcapCveMatches).where(PcapCveMatches.run_id == run_id).limit(100)
    )).scalars().all()

    return {
        "schema_version": 1,
        "run_id": run.run_id,
        "evidence_id": run.evidence_id,
        "investigation_id": run.investigation_id,
        "status": run.status,
        "current_step": run.current_step,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "error_message": run.error_message,
        "severity": {
            "overall_score": float(score_row.overall_score),
            "overall_severity": score_row.overall_severity,
            "cvss_base_max": float(score_row.cvss_base_max or 0.0),
            "ioc_risk_score": float(score_row.ioc_risk_score or 0.0),
            "anomaly_score": float(score_row.anomaly_score or 0.0),
            "factors": score_row.factors,
            "calculated_at": score_row.calculated_at.isoformat() if score_row.calculated_at else None,
        } if score_row else None,
        "flows": [
            {
                "id": f.id,
                "src_ip": str(f.src_ip),
                "dst_ip": str(f.dst_ip),
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "packet_count": f.packet_count,
                "byte_count": f.byte_count,
                "bidirectional": f.bidirectional,
                "duration_seconds": f.duration_seconds,
                "flags": f.flags,
            }
            for f in flows
        ],
        "sessions": [
            {
                "id": s.id,
                "src_ip": str(s.src_ip),
                "dst_ip": str(s.dst_ip),
                "src_port": s.src_port,
                "dst_port": s.dst_port,
                "state": s.state,
                "client_isn": s.client_isn,
                "server_isn": s.server_isn,
                "reassembled_bytes": s.reassembled_bytes,
                "confidence": s.confidence,
                "payload_truncated": s.payload_truncated,
            }
            for s in tcp_sessions
        ],
        "artifacts": [
            {
                "id": a.id,
                "artifact_type": a.artifact_type,
                "content_type": a.content_type,
                "size_bytes": a.size_bytes,
                "sha256": a.sha256,
                "has_file": bool(a.storage_key),
                "metadata": a.metadata_json,
            }
            for a in artifacts
        ],
        "iocs": [
            {
                "id": i.id,
                "ioc_type": i.ioc_type,
                "ioc_value": i.ioc_value,
                "is_allowlisted": i.is_allowlisted,
                "threat_intel_match": i.threat_intel_match,
                "context": i.context,
            }
            for i in iocs
        ],
        "cve_matches": [
            {
                "id": c.id,
                "cve_id": c.cve_id,
                "cvss_score": float(c.cvss_score) if c.cvss_score is not None else None,
                "severity": c.severity,
                "match_type": c.match_type,
                "confidence": c.confidence,
                "description": c.description,
                "matched_data": c.matched_data,
            }
            for c in cves
        ],
    }


@router.post("/{investigation_id}/analysis/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_pcap_analysis_endpoint(
    investigation_id: int = Path(..., ge=1),
    evidence_id: Optional[int] = Query(None, ge=1),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_admin),
) -> dict[str, Any]:
    inv = (await session.execute(
        select(AgentInvestigation.id).where(AgentInvestigation.id == investigation_id)
    )).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    if evidence_id:
        ev = (await session.execute(
            select(InvestigationEvidence).where(
                InvestigationEvidence.id == evidence_id,
                InvestigationEvidence.investigation_id == investigation_id,
            )
        )).scalar_one_or_none()
        if ev is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    else:
        ev = (await session.execute(
            select(InvestigationEvidence)
            .where(
                InvestigationEvidence.investigation_id == investigation_id,
                InvestigationEvidence.status == "complete",
            )
            .order_by(InvestigationEvidence.captured_at.desc(), InvestigationEvidence.id.desc())
            .limit(1)
        )).scalar_one_or_none()
        if ev is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No complete PCAP evidence available for this investigation",
            )

    run_id = start_pcap_analysis(ev.id)
    return {
        "status": "pending",
        "run_id": run_id,
        "evidence_id": ev.id,
        "investigation_id": investigation_id,
    }


@router.get("/{investigation_id}/analysis/{run_id}/artifacts/{artifact_id}/download")
async def download_pcap_artifact(
    investigation_id: int = Path(..., ge=1),
    run_id: str = Path(..., min_length=1),
    artifact_id: int = Path(..., ge=1),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> FileResponse:
    art = (await session.execute(
        select(PcapArtifacts).where(
            PcapArtifacts.id == artifact_id,
            PcapArtifacts.run_id == run_id,
        )
    )).scalar_one_or_none()
    if art is None or not art.storage_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact file not found")

    storage = get_storage_backend()
    file_path = (storage.root / art.storage_key).resolve()
    try:
        file_path.relative_to(storage.root)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid artifact storage path")

    if not file_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact file missing from disk")

    filename = file_path.name
    media_type = art.content_type or "application/octet-stream"
    return FileResponse(
        file_path,
        media_type=media_type,
        filename=filename,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=InvestigationResponse,
    responses={503: {"description": "Investigation job could not be queued"}},
)
async def trigger_investigation(
    req: InvestigationCreateRequest,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_admin),
) -> Dict[str, Any]:
    node = await NodeService.get_node(req.node_id, session)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {req.node_id} not found",
        )

    if req.trigger_type == "alert":
        trigger = (await session.execute(select(AlertEvent).where(
            AlertEvent.id == req.trigger_id, AlertEvent.node_id == req.node_id
        ))).scalar_one_or_none()
    elif req.trigger_type == "anomaly":
        trigger = (await session.execute(select(AnomalyEvent).where(
            AnomalyEvent.id == req.trigger_id, AnomalyEvent.node_id == req.node_id
        ))).scalar_one_or_none()
    else:
        trigger = None
    if req.trigger_type in {"alert", "anomaly"} and trigger is None:
        raise HTTPException(status_code=404, detail="Trigger event not found for this node")

    investigation, dispatched = await enqueue_investigation_async(
        session,
        node_id=req.node_id,
        trigger_type=req.trigger_type,
        trigger_id=req.trigger_id,
    )
    if not dispatched:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"message": "Investigation dispatch failed", "investigation_id": investigation.id},
        )
    return _serialize(investigation)


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(
    investigation_id: int = Path(..., ge=1, description="Investigation ID to delete"),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_admin),
) -> None:
    stmt = select(AgentInvestigation).where(AgentInvestigation.id == investigation_id)
    row = (await session.execute(stmt)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    storage_keys = (await session.execute(
        select(InvestigationEvidence.storage_key).where(
            InvestigationEvidence.investigation_id == investigation_id,
            InvestigationEvidence.storage_key.is_not(None),
        )
    )).scalars().all()
    await session.delete(row)
    await session.commit()
    for storage_key in storage_keys:
        try:
            _root, file_path = _resolve_evidence_path(storage_key)
            file_path.unlink(missing_ok=True)
            try:
                file_path.parent.rmdir()
            except OSError:
                pass
        except (OSError, ValueError):
            logger.warning("Could not remove stored evidence %s for deleted investigation %s", storage_key, investigation_id, exc_info=True)
