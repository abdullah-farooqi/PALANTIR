from fastapi import APIRouter, Header, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from core.config import settings
from core.database import get_session
from services.alerts import AlertService

router = APIRouter()


@router.post("/alert")
async def receive_alert(
    payload: dict,
    x_palantir_secret: str = Header(None, alias="X-PALANTIR-Secret"),
    session: AsyncSession = Depends(get_session),
):
    """
    Receives push webhook from Netdata agent's health_alarm_notify.
    Validates shared secret and delegates to AlertService.
    """
    if x_palantir_secret != settings.PALANTIR_WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")

    service = AlertService()
    event = await service.receive_and_classify(payload, session)
    if not event:
        return {"status": "ignored", "reason": "unregistered node or invalid payload"}

    return {"status": "received", "event_id": event.id}
