from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc, update
from typing import Optional, List
from datetime import datetime, timezone
from app.database import get_db
from app.models import (
    Notification, NotificationStatus, Incident, IncidentStatus, IncidentSeverity,
    User, Group, DeliveryLog, DeliveryStatus, NotificationResponse as NRModel,
    AuditLog, AlertChannel, UserRole
)
from app.schemas import (
    NotificationCreate, NotificationResponse, NotificationDetailResponse,
    DeliveryLogResponse, NotificationResponseCreate, NotificationResponseOut,
    IncidentCreate, IncidentUpdate, IncidentResponse
)
from app.core.deps import get_current_user, require_admin, require_manager
from app.tasks import send_notification_task
from app.services.messaging import _is_safe_url
from app.services.rate_limiter import (
    check_notification_rate_limit,
    record_notification_dispatch,
    NOTIFICATION_RATE_LIMIT_MAX,
)

# ─── INCIDENT STATUS TRANSITIONS ──────────────────────────────────────────────

# Define valid status transitions for incidents
# Key = current status, Value = list of allowed next statuses
VALID_INCIDENT_STATUS_TRANSITIONS = {
    IncidentStatus.ACTIVE: [IncidentStatus.RESOLVED, IncidentStatus.CANCELLED],
    IncidentStatus.RESOLVED: [],  # Terminal state - no transitions allowed
    IncidentStatus.CANCELLED: [],  # Terminal state - no transitions allowed
}


def _validate_incident_status_transition(
    current_status: IncidentStatus,
    new_status: IncidentStatus
) -> bool:
    """Validate if a status transition is allowed.
    
    Args:
        current_status: Current incident status
        new_status: Desired new status
        
    Returns:
        True if transition is valid, False otherwise
    """
    allowed_transitions = VALID_INCIDENT_STATUS_TRANSITIONS.get(current_status, [])
    return new_status in allowed_transitions


# ─── INCIDENTS ────────────────────────────────────────────────────────────────

incidents_router = APIRouter(prefix="/incidents", tags=["Incidents"])


@incidents_router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    limit: int = Query(1, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List incidents with optional filtering by status and severity.
    
    Args:
        status: Filter by incident status (active, resolved, cancelled)
        severity: Filter by incident severity (low, medium, high, critical)
        limit: Maximum number of results (1-100, default 20)
    """
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
        user_email=current_user.email,
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

    # Validate status transition if status is being changed
    if data.status is not None and data.status != incident.status:
        if not _validate_incident_status_transition(incident.status, data.status):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status transition from '{incident.status.value}' to '{data.status.value}'. "
                       f"Allowed transitions: {[s.value for s in VALID_INCIDENT_STATUS_TRANSITIONS.get(incident.status, [])]}"
            )
        
        # Set resolution metadata if transitioning to RESOLVED
        if data.status == IncidentStatus.RESOLVED:
            incident.resolved_at = datetime.now(timezone.utc)
            incident.resolved_by_id = current_user.id

    # Use exclude_unset=True to allow clearing fields to None
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)

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


@notifications_router.get("", response_model=dict)
def list_notifications(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    incident_id: Optional[int] = None,
    status: Optional[NotificationStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List notifications with optional filtering.
    
    Access Control:
        - Manager and Admin roles: Can see all notifications
        - Viewer role: Can only see notifications where they are recipients
    """
    query = db.query(Notification)
    
    # Viewer-role users can only see notifications where they are recipients
    if current_user.role == UserRole.VIEWER:
        # Show notifications where: target_all=True OR user is in target_users OR user is in target_groups
        from sqlalchemy import or_
        query = query.filter(
            or_(
                Notification.target_all == True,
                Notification.target_users.any(User.id == current_user.id),
                Notification.target_groups.any(Group.members.any(User.id == current_user.id))
            )
        )
    
    if incident_id:
        query = query.filter(Notification.incident_id == incident_id)
    if status:
        query = query.filter(Notification.status == status)

    # Get total count
    total = query.count()

    # Get paginated results and convert to dict
    items = query.order_by(desc(Notification.created_at)).offset((page - 1) * page_size).limit(page_size).all()
    
    # Convert SQLAlchemy models to dict for JSON serialization
    items_data = []
    for item in items:
        items_data.append({
            "id": item.id,
            "incident_id": item.incident_id,
            "title": item.title,
            "message": item.message,
            "subject": item.subject,
            "channels": item.channels,
            "status": item.status.value if item.status else None,
            "target_all": item.target_all,
            "scheduled_at": item.scheduled_at.isoformat() if item.scheduled_at else None,
            "sent_at": item.sent_at.isoformat() if item.sent_at else None,
            "total_recipients": item.total_recipients,
            "sent_count": item.sent_count,
            "delivered_count": item.delivered_count,
            "failed_count": item.failed_count,
            "response_required": item.response_required,
            "response_deadline_minutes": item.response_deadline_minutes,
            "created_by_id": item.created_by_id,
            "created_at": item.created_at.isoformat() if item.created_at else None,
        })
    
    return {"items": items_data, "total": total, "page": page, "page_size": page_size}


@notifications_router.post("", response_model=NotificationResponse, status_code=201)
async def create_notification(
    data: NotificationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    # Rate limiting: Check if user has exceeded notification dispatch limit
    is_allowed, retry_after = await check_notification_rate_limit(current_user.id)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {NOTIFICATION_RATE_LIMIT_MAX} notifications per minute.",
            headers={"Retry-After": str(retry_after)}
        )

    # Validate at least one recipient method
    if not data.target_all and not data.target_group_ids and not data.target_user_ids:
        raise HTTPException(status_code=400, detail="Must specify recipients: target_all, groups, or users")

    # Validate webhook URLs to prevent SSRF attacks
    if data.slack_webhook_url and not _is_safe_url(data.slack_webhook_url):
        raise HTTPException(
            status_code=400,
            detail="Invalid Slack webhook URL. URLs must use HTTP/HTTPS and cannot point to internal/private addresses"
        )
    if data.teams_webhook_url and not _is_safe_url(data.teams_webhook_url):
        raise HTTPException(
            status_code=400,
            detail="Invalid Teams webhook URL. URLs must use HTTP/HTTPS and cannot point to internal/private addresses"
        )

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
        user_email=current_user.email,
        action="create_notification",
        resource_type="notification",
        details={"title": data.title, "channels": [c.value for c in data.channels]}
    ))
    db.commit()
    db.refresh(notification)

    # Record this dispatch for rate limiting
    await record_notification_dispatch(current_user.id)

    # Send immediately if not scheduled (task will change status to SENT when complete)
    if not data.scheduled_at:
        send_notification_task.delay(notification.id)

    return notification


@notifications_router.post("/{notification_id}/send", response_model=NotificationResponse)
async def send_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    """Manually trigger a draft notification.
    
    Rate Limit: Maximum 10 notifications per minute per user.
    """
    # Rate limiting: Check if user has exceeded notification dispatch limit
    is_allowed, retry_after = await check_notification_rate_limit(current_user.id)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {NOTIFICATION_RATE_LIMIT_MAX} notifications per minute.",
            headers={"Retry-After": str(retry_after)}
        )

    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notification.status not in [NotificationStatus.DRAFT, NotificationStatus.SCHEDULED]:
        raise HTTPException(status_code=400, detail=f"Cannot send notification in {notification.status} state")

    send_notification_task.delay(notification_id)
    
    # Record this dispatch for rate limiting
    await record_notification_dispatch(current_user.id)
    
    db.add(AuditLog(
        user_id=current_user.id,
        user_email=current_user.email,
        action="send_notification",
        resource_type="notification",
        resource_id=notification_id
    ))
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
    """Get notification details.
    
    Access Control:
        - Manager and Admin roles: Can see all notifications
        - Viewer role: Can only see notifications where they are recipients
    """
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    # Viewer-role users can only see notifications where they are recipients
    if current_user.role == UserRole.VIEWER:
        from sqlalchemy import or_
        is_recipient = (
            notification.target_all or
            any(u.id == current_user.id for u in notification.target_users) or
            any(g.members and any(m.id == current_user.id for m in g.members) for g in notification.target_groups)
        )
        if not is_recipient:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only view notifications where you are a recipient."
            )

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
    status: Optional[DeliveryStatus] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get delivery logs for a notification with optional filtering.

    Args:
        notification_id: ID of the notification
        channel: Filter by delivery channel (sms, email, voice, web)
        status: Filter by delivery status (pending, sent, delivered, failed, bounced)
        limit: Maximum number of results (1-1000, default 100)
        offset: Number of results to skip (default 0)
    """
    query = db.query(DeliveryLog).filter(DeliveryLog.notification_id == notification_id)
    if channel:
        query = query.filter(DeliveryLog.channel == channel)
    if status:
        query = query.filter(DeliveryLog.status == status)
    logs = query.order_by(desc(DeliveryLog.id)).offset(offset).limit(limit).all()

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
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get notification responses.

    Args:
        notification_id: ID of the notification
    """
    query = db.query(NRModel).filter(NRModel.notification_id == notification_id)
    responses = query.all()
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

    # Create the response record with WEB channel
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

    # Create delivery log entry to track web delivery (mark as delivered when user responds)
    # Check if delivery log already exists to avoid duplicates
    existing_log = db.query(DeliveryLog).filter(
        DeliveryLog.notification_id == notification_id,
        DeliveryLog.user_id == current_user.id,
        DeliveryLog.channel == AlertChannel.WEB
    ).first()

    if not existing_log:
        delivery_log = DeliveryLog(
            notification_id=notification_id,
            user_id=current_user.id,
            user_email=current_user.email,
            channel=AlertChannel.WEB,
            status=DeliveryStatus.DELIVERED,
            delivered_at=datetime.now(timezone.utc)
        )
        db.add(delivery_log)
        # Atomically increment delivered_count
        db.execute(
            update(Notification)
            .where(Notification.id == notification_id)
            .values(delivered_count=Notification.delivered_count + 1)
        )

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
