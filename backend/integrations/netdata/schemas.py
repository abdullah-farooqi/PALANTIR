from pydantic import BaseModel, Field
from typing import Any, List, Dict


class NetdataResult(BaseModel):
    labels: List[str]
    data: List[List[Any]]


class NetdataDataResponse(BaseModel):
    result: NetdataResult


class NetdataWeightsResponse(BaseModel):
    result: Dict[str, Any]


class NetdataInfoResponse(BaseModel):
    version: str
    uid: str
    mirrored_hosts: List[str] = Field(default_factory=list)
