from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class InvestigationNodeEvidence(_StrictContract):
    id: int
    hostname: str = Field(max_length=253)


class InvestigationTriggerEvidence(_StrictContract):
    type: Literal["manual", "alert", "anomaly"]
    id: int | None = None
    severity: Literal["WARNING", "CRITICAL"] | None = None
    alert_name: str | None = Field(default=None, max_length=255)
    chart: str | None = Field(default=None, max_length=255)
    received_at: datetime | None = None
    detected_at: datetime | None = None
    contexts: list[str] = Field(default_factory=list, max_length=16)
    scores: dict[str, float] = Field(default_factory=dict, max_length=16)
    max_score: float | None = None


class InvestigationMetricEvidence(_StrictContract):
    category: str = Field(max_length=32)
    source: str = Field(max_length=32)
    collected_at: datetime
    metrics: dict[str, float] = Field(max_length=5)


class InvestigationAlertEvidence(_StrictContract):
    id: int
    alert_name: str = Field(max_length=255)
    chart: str = Field(max_length=255)
    severity: Literal["WARNING", "CRITICAL"]
    received_at: datetime


class InvestigationAnomalyEvidence(_StrictContract):
    id: int
    detected_at: datetime
    contexts: list[str] = Field(max_length=16)
    scores: dict[str, float] = Field(max_length=16)
    max_score: float


class InvestigationWindow(_StrictContract):
    since: datetime
    until: datetime


class InvestigationEvidence(_StrictContract):
    latest_metrics: list[InvestigationMetricEvidence] = Field(max_length=16)
    active_alerts: list[InvestigationAlertEvidence] = Field(max_length=10)
    recent_anomalies: list[InvestigationAnomalyEvidence] = Field(max_length=10)


class InvestigationAssessment(_StrictContract):
    result: Literal["evidence_collected"]
    root_cause_inferred: Literal[False]


class InvestigationEvidenceResult(_StrictContract):
    schema_version: Literal[1]
    kind: Literal["telemetry_evidence_summary"]
    generated_at: datetime
    node: InvestigationNodeEvidence
    trigger: InvestigationTriggerEvidence
    window: InvestigationWindow
    evidence: InvestigationEvidence
    assessment: InvestigationAssessment
