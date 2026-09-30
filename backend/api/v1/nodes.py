import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from core.security import validate_netdata_url
from services.nodes import NodeService
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
    os_type: str = Field(
        default="linux",
        min_length=1,
        max_length=32,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Operating system type",
    )

    model_config = {"extra": "forbid"}

    @field_validator("netdata_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        try:
            return validate_netdata_url(v)
        except ValueError as err:
            raise ValueError(f"Invalid netdata_url: {err}")


class NodeResponse(BaseModel):
    id: int
    hostname: str
    netdata_url: str
    os_type: str
    active: bool
    context_count: Optional[int] = None
    alert_count: Optional[int] = None

    model_config = {"from_attributes": True}


@router.get("", response_model=List[NodeResponse])
async def list_monitored_nodes(
    active_only: bool = True,
    session: AsyncSession = Depends(get_session),
):
    nodes = await NodeService.list_nodes(session, active_only=active_only)
    return nodes


@router.post("", response_model=NodeResponse, status_code=status.HTTP_201_CREATED)
async def register_monitored_node(
    req: NodeRegisterRequest,
    session: AsyncSession = Depends(get_session),
):
    try:
        node = await NodeService.register_node(
            hostname=req.hostname,
            netdata_url=req.netdata_url,
            os_type=req.os_type,
            session=session,
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
):
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return node


@router.delete("/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_monitored_node(
    node_id: int = Path(..., ge=1, description="Monitored node ID"),
    session: AsyncSession = Depends(get_session),
):
    success = await NodeService.deactivate_node(node_id, session)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

