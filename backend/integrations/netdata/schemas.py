from pydantic import BaseModel, ConfigDict, Field
from typing import Any, List, Dict, Union, Optional


class NetdataResult(BaseModel):
    labels: List[str] = Field(default_factory=list)
    data: List[List[Any]] = Field(default_factory=list)
    point: Any = None


class NetdataDataResponse(BaseModel):
    result: NetdataResult = Field(default_factory=NetdataResult)


class NetdataWeightsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    result: Optional[Union[Dict[str, Any], List[Any]]] = Field(default_factory=dict)
    request: Dict[str, Any] = Field(default_factory=dict)
    response_schema: Dict[str, Any] = Field(default_factory=dict, alias="schema")
    dictionaries: Dict[str, Any] = Field(default_factory=dict)


class NetdataInfoResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    version: str = ""
    uid: str = ""
    mirrored_hosts: List[str] = Field(default_factory=list)
    ram_total: Optional[Union[str, int, float]] = None
    host_labels: Dict[str, Any] = Field(default_factory=dict)
    ml_info: Dict[str, Any] = Field(default_factory=dict, alias="ml-info")
    memory_mode: Any = Field(default=None, alias="memory-mode")
    cloud_enabled: bool = Field(default=False, alias="cloud-enabled")
    agent_claimed: bool = Field(default=False, alias="agent-claimed")


class NetdataV3InfoResponse(BaseModel):
    """Flexible envelope returned by the host's /api/v3/info endpoint."""

    api: Optional[int] = None
    agents: List[Dict[str, Any]] = Field(default_factory=list)
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    timings: Dict[str, Any] = Field(default_factory=dict)
