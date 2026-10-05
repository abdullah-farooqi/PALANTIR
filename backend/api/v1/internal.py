from typing import Optional
from fastapi import APIRouter, Header, HTTPException, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from core.security import verify_webhook_secret
from services.alerts import AlertService

router = APIRouter()


class AlertWebhookPayload(BaseModel):
    node: str = Field(..., min_length=1, max_length=253, description="Node hostname or identifier")
    alert: str = Field(default="unknown", min_length=1, max_length=255, description="Alert or alarm name")
    chart: str = Field(default="unknown", min_length=1, max_length=255, description="Chart identifier")
    status: str = Field(default="CLEAR", min_length=1, max_length=32, description="Alert status (e.g. CLEAR, WARNING, CRITICAL)")
    value: Optional[float] = Field(default=None, description="Numeric metric value")
    units: Optional[str] = Field(default=None, max_length=64, description="Metric units")
    timestamp: Optional[float] = Field(default=None, description="Event Unix timestamp")

    model_config = {
        "extra": "ignore"
    }


@router.post("/alert")
async def receive_alert(
    payload: AlertWebhookPayload,
    x_palantir_secret: Optional[str] = Header(None, alias="X-PALANTIR-Secret"),
    session: AsyncSession = Depends(get_session),
):
    """
    Receives push webhook from Netdata agent's health_alarm_notify.
    Validates shared secret using constant-time comparison to eliminate timing attacks.
    Enforces strict Pydantic payload validation and sanitization.
    """
    if not verify_webhook_secret(x_palantir_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid secret",
        )

    service = AlertService()
    event = await service.receive_and_classify(payload, session)
    if not event:
        return {"status": "ignored", "reason": "unregistered node or invalid payload"}

    return {
        "status": "received",
        "event_id": event.id,
        "investigation_id": event.investigation_id,
    }
