from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional, List
from datetime import datetime, timezone
from app.database import get_db
from app.models import (
    Notification, NotificationStatus, Incident, IncidentStatus,
    User, Group, DeliveryLog, NotificationResponse as NRModel,
    AuditLog, AlertChannel
)
from app.schemas import (
    NotificationCreate, NotificationResponse, NotificationDetailResponse,
    DeliveryLogResponse, NotificationResponseCreate, NotificationResponseOut,
    IncidentCreate, IncidentUpdate, IncidentResponse
)
from app.core.deps import get_current_user, require_manager
from app.tasks import send_notification_task

# ─── INCIDENTS ────────────────────────────────────────────────────────────────

incidents_router = APIRouter(prefix="/incidents", tags=["Incidents"])


@incidents_router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[IncidentStatus] = None,
    severity: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    return query.order_by(desc(Incident.created_at)).limit(limit).all()


@incidents_router.post("", response_model=IncidentResponse, status_code=201)
def create_incident(
    data: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    incident = Incident(**data.model_dump(), created_by_id=current_user.id)
    db.add(incident)
    db.add(AuditLog(
        user_id=current_user.id,
        action="create_incident",
        resource_type="incident",
        details={"title": data.title, "severity": data.severity}
    ))
    db.commit()
    db.refresh(incident)
    return incident


@incidents_router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Use exclude_unset=True to allow clearing fields to None
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)

    if data.status == IncidentStatus.RESOLVED:
        incident.resolved_at = datetime.now(timezone.utc)
        incident.resolved_by_id = current_user.id

    db.commit()
    db.refresh(incident)
    return incident


@incidents_router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


# ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

notifications_router = APIRouter(prefix="/notifications", tags=["Notifications"])


@notifications_router.get("", response_model=List[NotificationResponse])
def list_notifications(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    incident_id: Optional[int] = None,
    status: Optional[NotificationStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Notification)
    if incident_id:
        query = query.filter(Notification.incident_id == incident_id)
    if status:
        query = query.filter(Notification.status == status)
    return query.order_by(desc(Notification.created_at)).offset((page - 1) * page_size).limit(page_size).all()


@notifications_router.post("", response_model=NotificationResponse, status_code=201)
def create_notification(
    data: NotificationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    # Validate at least one recipient method
    if not data.target_all and not data.target_group_ids and not data.target_user_ids:
        raise HTTPException(status_code=400, detail="Must specify recipients: target_all, groups, or users")

    notification = Notification(
        incident_id=data.incident_id,
        template_id=data.template_id,
        title=data.title,
        message=data.message,
        subject=data.subject,
        channels=[c.value for c in data.channels],
        target_all=data.target_all,
        scheduled_at=data.scheduled_at,
        response_required=data.response_required,
        response_deadline_minutes=data.response_deadline_minutes,
        slack_webhook_url=data.slack_webhook_url,
        teams_webhook_url=data.teams_webhook_url,
        created_by_id=current_user.id,
        # Set status to SENDING for immediate send, SCHEDULED for future
        status=NotificationStatus.SCHEDULED if data.scheduled_at else NotificationStatus.SENDING
    )

    if data.target_group_ids:
        groups = db.query(Group).filter(Group.id.in_(data.target_group_ids)).all()
        notification.target_groups = groups

    if data.target_user_ids:
        users = db.query(User).filter(User.id.in_(data.target_user_ids)).all()
        notification.target_users = users

    db.add(notification)
    db.add(AuditLog(
        user_id=current_user.id,
        action="create_notification",
        resource_type="notification",
        details={"title": data.title, "channels": [c.value for c in data.channels]}
    ))
    db.commit()
    db.refresh(notification)

    # Send immediately if not scheduled (task will change status to SENT when complete)
    if not data.scheduled_at:
        send_notification_task.delay(notification.id)

    return notification


@notifications_router.post("/{notification_id}/send", response_model=NotificationResponse)
def send_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    """Manually trigger a draft notification."""
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notification.status not in [NotificationStatus.DRAFT, NotificationStatus.SCHEDULED]:
        raise HTTPException(status_code=400, detail=f"Cannot send notification in {notification.status} state")

    send_notification_task.delay(notification_id)
    db.add(AuditLog(user_id=current_user.id, action="send_notification", resource_type="notification", resource_id=notification_id))
    db.commit()
    db.refresh(notification)
    return notification


@notifications_router.post("/{notification_id}/cancel")
def cancel_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notification.status not in [NotificationStatus.DRAFT, NotificationStatus.SCHEDULED]:
        raise HTTPException(status_code=400, detail="Can only cancel draft or scheduled notifications")
    notification.status = NotificationStatus.CANCELLED
    db.commit()
    return {"message": "Notification cancelled"}


@notifications_router.get("/{notification_id}", response_model=NotificationDetailResponse)
def get_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    delivery_stats = _get_delivery_stats(db, notification_id)
    response_stats = _get_response_stats(db, notification_id)

    result = NotificationDetailResponse.model_validate(notification)
    result.delivery_stats = delivery_stats
    result.response_stats = response_stats
    return result


@notifications_router.get("/{notification_id}/delivery", response_model=List[DeliveryLogResponse])
def get_delivery_logs(
    notification_id: int,
    channel: Optional[AlertChannel] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(DeliveryLog).filter(DeliveryLog.notification_id == notification_id)
    if channel:
        query = query.filter(DeliveryLog.channel == channel)
    if status:
        query = query.filter(DeliveryLog.status == status)
    logs = query.all()

    result = []
    for log in logs:
        result.append(DeliveryLogResponse(
            id=log.id,
            user_id=log.user_id,
            user_name=log.user.full_name if log.user else None,
            channel=log.channel,
            status=log.status,
            to_address=log.to_address,
            error_message=log.error_message,
            sent_at=log.sent_at,
            delivered_at=log.delivered_at
        ))
    return result


@notifications_router.get("/{notification_id}/responses", response_model=List[NotificationResponseOut])
def get_responses(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    responses = db.query(NRModel).filter(NRModel.notification_id == notification_id).all()
    result = []
    for r in responses:
        result.append(NotificationResponseOut(
            id=r.id,
            notification_id=r.notification_id,
            user_id=r.user_id,
            user_name=r.user.full_name if r.user else r.from_number,
            channel=r.channel,
            response_type=r.response_type,
            message=r.message,
            latitude=r.latitude,
            longitude=r.longitude,
            responded_at=r.responded_at
        ))
    return result


@notifications_router.post("/{notification_id}/respond")
def submit_response(
    notification_id: int,
    data: NotificationResponseCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Employee submits their safety response via the web portal."""
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    response = NRModel(
        notification_id=notification_id,
        user_id=current_user.id,
        channel=AlertChannel.WEB,
        response_type=data.response_type,
        message=data.message,
        latitude=data.latitude,
        longitude=data.longitude
    )
    db.add(response)
    db.commit()
    return {"message": "Response recorded", "response_type": data.response_type}


def _get_delivery_stats(db: Session, notification_id: int) -> dict:
    logs = db.query(DeliveryLog).filter(DeliveryLog.notification_id == notification_id).all()
    stats = {"total": len(logs), "sent": 0, "delivered": 0, "failed": 0, "pending": 0, "by_channel": {}}
    for log in logs:
        stats[log.status.value] = stats.get(log.status.value, 0) + 1
        ch = log.channel.value
        if ch not in stats["by_channel"]:
            stats["by_channel"][ch] = {"sent": 0, "delivered": 0, "failed": 0}
        stats["by_channel"][ch][log.status.value] = stats["by_channel"][ch].get(log.status.value, 0) + 1
    return stats


def _get_response_stats(db: Session, notification_id: int) -> dict:
    responses = db.query(NRModel).filter(NRModel.notification_id == notification_id).all()
    stats = {"total": len(responses), "safe": 0, "need_help": 0, "acknowledged": 0}
    for r in responses:
        stats[r.response_type.value] = stats.get(r.response_type.value, 0) + 1
    return stats
