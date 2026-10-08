import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, Field, computed_field, field_validator
from sqlalchemy import and_, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from core.api_auth import require_admin, require_node_enrollment, require_read
from core.security import validate_netdata_url
from models.node import MonitoredNode
from models.category_status import CategoryCollectionStatus
from services.nodes import NodeService
from services.collection_status import summarize_category_statuses
from core.config import settings
from core.cursors import decode_cursor, encode_cursor
from integrations.netdata.exceptions import NetdataUnavailable

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/nodes", tags=["Nodes"])


class NodeRegisterRequest(BaseModel):
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=253,
        pattern=r"^[a-zA-Z0-9_\.\-]+$",
        description="Node hostname",
    )
    netdata_url: str = Field(
        ...,
        min_length=7,
        max_length=2048,
        description="Base URL of the Netdata agent",
    )
    collector_url: Optional[str] = Field(
        default=None,
        min_length=7,
        max_length=2048,
        description="Optional base URL of the PALANTIR Linux host collector",
    )
    os_type: str = Field(
        default="linux",
        min_length=1,
        max_length=64,
        description="Operating system type or distro name",
    )

    model_config = {"extra": "forbid"}

    @field_validator("netdata_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        try:
            return validate_netdata_url(v)
        except ValueError as err:
            raise ValueError(f"Invalid netdata_url: {err}")

    @field_validator("collector_url")
    @classmethod
    def validate_collector_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return validate_netdata_url(v)
        except ValueError as err:
            raise ValueError(f"Invalid collector_url: {err}")

    @field_validator("os_type", mode="before")
    @classmethod
    def normalize_os_type(cls, value: str) -> str:
        return value.strip().lower() if isinstance(value, str) else value


class NodeResponse(BaseModel):
    id: int
    hostname: str
    netdata_url: str
    collector_url: Optional[str] = None
    capabilities: Optional[dict] = None
    os_type: str
    active: bool
    context_count: Optional[int] = None
    alert_count: Optional[int] = None
    last_seen_at: datetime
    last_collection_at: Optional[datetime] = None

    @computed_field
    @property
    def reachability(self) -> str:
        seen_at = self.last_seen_at
        if seen_at.tzinfo is None:
            seen_at = seen_at.replace(tzinfo=timezone.utc)
        age_seconds = max(0.0, (datetime.now(timezone.utc) - seen_at).total_seconds())
        if age_seconds <= settings.NODE_REACHABLE_SECONDS:
            return "reachable"
        if age_seconds <= settings.NODE_STALE_SECONDS:
            return "stale"
        return "unreachable"

    @computed_field
    @property
    def active_alerts_count(self) -> int:
        if not hasattr(self, "alert_events") or not self.alert_events:
            return 0
        return sum(1 for a in self.alert_events if getattr(a, "status", "") in {"WARNING", "CRITICAL", "active"})

    model_config = {"from_attributes": True}


class NodeSearchResponse(BaseModel):
    schema_version: int
    filters: dict
    items: List[NodeResponse]
    has_more: bool
    next_cursor: Optional[str] = None


@router.get("", response_model=List[NodeResponse])
async def list_monitored_nodes(
    active_only: bool = True,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
):
    nodes = await NodeService.list_nodes(session, active_only=active_only)
    return nodes


@router.get("/search", response_model=NodeSearchResponse)
async def search_monitored_nodes(
    q: Optional[str] = Query(default=None, max_length=253),
    active: Optional[bool] = None,
    os_type: Optional[str] = Query(default=None, max_length=32),
    reachability: Optional[str] = Query(default=None, pattern="^(reachable|stale|unreachable)$"),
    capability_key: Optional[str] = Query(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$"),
    capability_value: Optional[str] = Query(default=None, max_length=256),
    category: Optional[str] = Query(default=None, max_length=32),
    category_status: Optional[str] = Query(
        default=None,
        pattern="^(available|not_configured|unsupported|stale|collection_error|unknown)$",
    ),
    source: Optional[str] = Query(default=None, pattern="^(netdata|palantir-agent)$"),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
):
    if bool(capability_key) != bool(capability_value):
        raise HTTPException(status_code=400, detail="capability_key and capability_value must be provided together")
    if category_status and not category:
        raise HTTPException(status_code=400, detail="category is required with category_status")
    if category_status and not source:
        raise HTTPException(status_code=400, detail="source is required with category_status")
    valid_categories = {"system", "storage", "network", "services", "processes", "connections", "containers", "vms"}
    if category and category not in valid_categories:
        raise HTTPException(status_code=400, detail="Unknown collection category")
    if os_type and not all(ch.isalnum() or ch in "_-" for ch in os_type):
        raise HTTPException(status_code=400, detail="Invalid os_type")

    try:
        position = decode_cursor(cursor, {"hostname", "id"})
        cursor_id = int(position["id"]) if position else None
        cursor_hostname = position["hostname"] if position else None
        if position and (not isinstance(cursor_hostname, str) or cursor_id <= 0):
            raise ValueError("Cursor is invalid")
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "Cursor is invalid") from exc

    now = datetime.now(timezone.utc)
    statement = select(MonitoredNode)
    if q:
        statement = statement.where(MonitoredNode.hostname.ilike(f"%{q}%"))
    if active is not None:
        statement = statement.where(MonitoredNode.active == active)
    if os_type:
        statement = statement.where(MonitoredNode.os_type == os_type.lower())
    if capability_key:
        statement = statement.where(
            MonitoredNode.capabilities.is_not(None),
            MonitoredNode.capabilities[capability_key].as_string() == capability_value,
        )
    if reachability == "reachable":
        statement = statement.where(MonitoredNode.last_seen_at >= now - timedelta(seconds=settings.NODE_REACHABLE_SECONDS))
    elif reachability == "stale":
        statement = statement.where(
            MonitoredNode.last_seen_at < now - timedelta(seconds=settings.NODE_REACHABLE_SECONDS),
            MonitoredNode.last_seen_at >= now - timedelta(seconds=settings.NODE_STALE_SECONDS),
        )
    elif reachability == "unreachable":
        statement = statement.where(MonitoredNode.last_seen_at < now - timedelta(seconds=settings.NODE_STALE_SECONDS))

    if category_status:
        status_conditions = []
        cutoff = now - timedelta(seconds=settings.METRIC_STALE_SECONDS)
        if category_status == "stale":
            status_conditions.append(and_(
                CategoryCollectionStatus.last_success_at.is_not(None),
                CategoryCollectionStatus.last_success_at < cutoff,
            ))
        elif category_status == "available":
            status_conditions.append(and_(
                CategoryCollectionStatus.last_success_at >= cutoff,
                CategoryCollectionStatus.status != "collection_error",
            ))
        elif category_status == "collection_error":
            status_conditions.append(and_(
                CategoryCollectionStatus.status == "collection_error",
                or_(CategoryCollectionStatus.last_success_at.is_(None), CategoryCollectionStatus.last_success_at >= cutoff),
            ))
        elif category_status == "unknown":
            has_unknown = exists(select(1).where(
                CategoryCollectionStatus.node_id == MonitoredNode.id,
                CategoryCollectionStatus.category == category,
                CategoryCollectionStatus.source == source,
                CategoryCollectionStatus.status == "unknown",
            ))
            source_expected = (
                source == "netdata" and category in {"system", "network", "processes", "containers"}
            ) or (source == "palantir-agent" and MonitoredNode.collector_url.is_not(None))
            missing_status = exists(select(1).where(
                CategoryCollectionStatus.node_id == MonitoredNode.id,
                CategoryCollectionStatus.category == category,
                CategoryCollectionStatus.source == source,
            ))
            statement = statement.where(or_(
                has_unknown,
                and_(source_expected, ~missing_status),
            ))
            status_conditions = []
        else:
            status_conditions.append(CategoryCollectionStatus.status == category_status)
        if status_conditions:
            matching_nodes = select(CategoryCollectionStatus.node_id).where(
                CategoryCollectionStatus.category == category,
                CategoryCollectionStatus.source == source,
                or_(*status_conditions),
            )
            statement = statement.where(MonitoredNode.id.in_(matching_nodes))

    if cursor_id is not None:
        statement = statement.where(or_(
            MonitoredNode.hostname > cursor_hostname,
            and_(MonitoredNode.hostname == cursor_hostname, MonitoredNode.id > cursor_id),
        ))
    statement = statement.order_by(MonitoredNode.hostname.asc(), MonitoredNode.id.asc()).limit(limit + 1)
    rows = (await session.execute(statement)).scalars().all()
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = encode_cursor({"hostname": page[-1].hostname, "id": page[-1].id}) if has_more and page else None
    return {
        "schema_version": 1,
        "filters": {"q": q, "active": active, "os_type": os_type, "reachability": reachability,
                    "capability_key": capability_key, "capability_value": capability_value,
                    "category": category, "category_status": category_status, "source": source},
        "items": [NodeResponse.model_validate(node) for node in page],
        "has_more": has_more,
        "next_cursor": next_cursor,
    }


@router.post("", response_model=NodeResponse, status_code=status.HTTP_201_CREATED)
async def register_monitored_node(
    req: NodeRegisterRequest,
    session: AsyncSession = Depends(get_session),
    api_role: str = Depends(require_node_enrollment),
):
    if api_role == "enroll":
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == req.hostname)
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing:
            if (
                existing.active
                and existing.netdata_url == req.netdata_url
                and existing.collector_url == req.collector_url
                and existing.os_type == req.os_type
            ):
                return existing
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Enrollment token cannot modify an existing node",
            )

    try:
        node = await NodeService.register_node(
            hostname=req.hostname,
            netdata_url=req.netdata_url,
            os_type=req.os_type,
            session=session,
            collector_url=req.collector_url,
        )
        return node
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except NetdataUnavailable as e:
        logger.warning(f"Netdata Agent unreachable during registration of {req.hostname}: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Netdata Agent unreachable or returned an invalid response",
        )
    except Exception as e:
        logger.exception(f"Unexpected failure registering node {req.hostname}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register node due to an internal error",
        )


@router.get("/{node_id}", response_model=NodeResponse)
async def get_monitored_node(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
):
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return node


@router.get("/{node_id}/capabilities")
async def get_node_capabilities(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
):
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return {
        "node_id": node.id,
        "hostname": node.hostname,
        "collector_url": node.collector_url,
        "capabilities": node.capabilities or {},
    }


@router.get("/{node_id}/collection-status")
async def get_node_collection_status(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
):
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    result = await session.execute(
        select(CategoryCollectionStatus).where(CategoryCollectionStatus.node_id == node_id)
    )
    categories = summarize_category_statuses(
        has_collector=bool(node.collector_url),
        rows=list(result.scalars().all()),
    )
    return {
        "schema_version": 1,
        "node_id": node.id,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "stale_after_seconds": settings.METRIC_STALE_SECONDS,
        "categories": categories,
    }


@router.delete("/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_monitored_node(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_admin),
):
    success = await NodeService.deactivate_node(node_id, session)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
