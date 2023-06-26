import logging
from functools import reduce

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from keep.api.core.db import get_session
from keep.api.core.dependencies import verify_api_key, verify_bearer_token
from keep.api.models.alert import AlertDto
from keep.api.models.db.alert import Alert
from keep.providers.providers_factory import ProvidersFactory

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get(
    "/",
    description="Get alerts",
)
def get_alerts(
    provider_type: str = None,
    provider_id: str = None,
    tenant_id: str = Depends(verify_api_key),
    session: Session = Depends(get_session),
) -> list[AlertDto]:
    query = session.query(Alert).filter(Alert.tenant_id == tenant_id)
    if provider_type:
        query = query.filter(Alert.provider_type == provider_type)
    if provider_id:
        if not provider_type:
            raise HTTPException(
                400, "provider_type is required when provider_id is set"
            )
        query = query.filter(Alert.provider_id == provider_id)
    alerts: list[Alert] = query.order_by(Alert.timestamp.desc()).all()
    # grouped_alerts = reduce(
    #     lambda acc, alert: acc.setdefault(alert.provider_type, []).append(alert) or acc,
    #     alerts,
    #     {},
    # )
    # alerts_dto: list[AlertDto] = []
    # for provider_type, alerts in grouped_alerts.items():
    #     provider_class = ProvidersFactory.get_provider_class(provider_type)
    #     alerts_dto.extend(provider_class.format_alert(alerts))
    return [alert.event for alert in alerts]


@router.post(
    "/event/{provider_type}", description="Receive an alert event from a provider"
)
def receive_event(
    provider_type: str,
    event: dict,
    provider_id: str | None = None,
    tenant_id: str = Depends(verify_bearer_token),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    logger.info(
        "Received event", extra={"provider_type": provider_type, "event": event}
    )
    provider_class = ProvidersFactory.get_provider_class(provider_type)
    try:
        logger.info(
            "Creating new alert in DB",
            extra={"provider_type": provider_type, "event": event},
        )
        # Each provider should implement a format_alert method that returns an AlertDto
        # object that will later be returned to the client.
        formatted_event = provider_class.format_alert(event)
        alert = Alert(
            tenant_id=tenant_id,
            provider_type=provider_type,
            event=formatted_event.dict(),
            provider_id=provider_id,
        )
        session.add(alert)
        session.commit()
        logger.info(
            "New alert created successfully",
            extra={"provider_type": provider_type, "event": event},
        )
        return {"status": "ok"}
    except Exception as e:
        logger.warn("Failed to create new alert", extra={"error": str(e)})
        return {"status": "failed"}
