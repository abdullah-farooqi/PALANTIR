from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from services.nodes import NodeService
from integrations.netdata.exceptions import NetdataUnavailable

router = APIRouter(prefix="/nodes", tags=["Nodes"])


class NodeRegisterRequest(BaseModel):
    hostname: str
    netdata_url: str
    os_type: str = "linux"


class NodeResponse(BaseModel):
    id: int
    hostname: str
    netdata_url: str
    os_type: str
    active: bool
    context_count: int | None = None
    alert_count: int | None = None

    class Config:
        from_attributes = True


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
    except NetdataUnavailable as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Netdata Agent unreachable: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to register node: {str(e)}",
        )


@router.get("/{node_id}", response_model=NodeResponse)
async def get_monitored_node(
    node_id: int,
    session: AsyncSession = Depends(get_session),
):
    node = await NodeService.get_node(node_id, session)
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return node


@router.delete("/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_monitored_node(
    node_id: int,
    session: AsyncSession = Depends(get_session),
):
    success = await NodeService.deactivate_node(node_id, session)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
