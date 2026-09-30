from pydantic import BaseModel, Field
from typing import Any, List, Dict, Union


class NetdataResult(BaseModel):
    labels: List[str]
    data: List[List[Any]]


class NetdataDataResponse(BaseModel):
    result: NetdataResult


class NetdataWeightsResponse(BaseModel):
    result: Union[Dict[str, Any], List[Any]] = Field(default_factory=dict)


class NetdataInfoResponse(BaseModel):
    version: str
    uid: str
    mirrored_hosts: List[str] = Field(default_factory=list)
