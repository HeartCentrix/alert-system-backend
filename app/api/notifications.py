from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc, update
from typing import Optional, List
from datetime import datetime, timezone
import logging
from app.database import get_db
from app.models import (
    Notification, NotificationStatus, Incident, IncidentStatus, IncidentSeverity,
    User, Group, DeliveryLog, DeliveryStatus, NotificationResponse as NRModel,
    AuditLog, AlertChannel, UserRole
)
from app.utils.audit import create_audit_log
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
    check_api_rate_limit,
    record_api_request,
    API_RATE_LIMIT_MAX,
)

logger = logging.getLogger(__name__)

# ─── INCIDENT STATUS TRANSITIONS ──────────────────────────────────────────────

# Incident lifecycle state machine
# ACTIVE → MONITORING → RESOLVED (standard resolution path)
# ACTIVE → RESOLVED              (fast-track if no monitoring period needed)
# ACTIVE → CANCELLED             (incident was raised in error or is no longer relevant)
# MONITORING → CANCELLED         (monitoring period ended without escalation needed)
# RESOLVED and CANCELLED are terminal — no further transitions permitted
VALID_INCIDENT_STATUS_TRANSITIONS = {
    IncidentStatus.ACTIVE:     [IncidentStatus.MONITORING, IncidentStatus.RESOLVED, IncidentStatus.CANCELLED],
    IncidentStatus.MONITORING: [IncidentStatus.RESOLVED, IncidentStatus.CANCELLED],
    IncidentStatus.RESOLVED:   [],   # terminal state
    IncidentStatus.CANCELLED:  [],   # terminal state
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
    limit: int = Query(20, ge=1, le=100),
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
    current_user: User = Depends(require_manager),
    request: Request = None,
):
    incident = Incident(**data.model_dump(), created_by_id=current_user.id)
    db.add(incident)
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="create_incident",
        resource_type="incident",
        details={"title": data.title, "severity": data.severity},
        request=request,
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
    current_user: User = Depends(require_manager),
    request: Request = None,
):
    # Rate limiting 1: Check general API rate limit for state-changing operations
    is_allowed, retry_after = await check_api_rate_limit(current_user.id, "create_notification")
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {API_RATE_LIMIT_MAX} requests per minute for this endpoint.",
            headers={"Retry-After": str(retry_after)}
        )
    
    # Rate limiting 2: Check notification-specific dispatch limit
    is_allowed, retry_after = await check_notification_rate_limit(current_user.id)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {NOTIFICATION_RATE_LIMIT_MAX} notifications per minute.",
            headers={"Retry-After": str(retry_after)}
        )
    
    # Record both rate limit counters
    await record_api_request(current_user.id, "create_notification")
    await record_notification_dispatch(current_user.id)

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

    # Validate timezone if provided
    scheduled_timezone = data.scheduled_timezone
    scheduled_at_utc = data.scheduled_at
    
    if data.scheduled_at and scheduled_timezone:
        # Convert scheduled time from local timezone to UTC
        try:
            import pytz
            local_tz = pytz.timezone(scheduled_timezone)
            # Assume the incoming datetime is naive (no timezone) and localize it
            local_dt = local_tz.localize(data.scheduled_at)
            # Convert to UTC
            scheduled_at_utc = local_dt.astimezone(pytz.UTC)
        except Exception as e:
            logger.warning(f"Invalid timezone '{scheduled_timezone}', using UTC: {e}")
            scheduled_at_utc = data.scheduled_at.replace(tzinfo=timezone.utc)
            scheduled_timezone = "UTC"
    elif data.scheduled_at and not scheduled_timezone:
        # Assume UTC if no timezone provided
        scheduled_at_utc = data.scheduled_at.replace(tzinfo=timezone.utc)
        scheduled_timezone = "UTC"

    notification = Notification(
        incident_id=data.incident_id,
        template_id=data.template_id,
        title=data.title,
        message=data.message,
        subject=data.subject,
        channels=[c.value for c in data.channels],
        target_all=data.target_all,
        scheduled_at=scheduled_at_utc,
        scheduled_timezone=scheduled_timezone,
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
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="create_notification",
        resource_type="notification",
        details={"title": data.title, "channels": [c.value for c in data.channels]},
        request=request,
    ))
    db.commit()
    db.refresh(notification)

    # Record this dispatch for rate limiting
    await record_notification_dispatch(current_user.id)

    # Send immediately if not scheduled (task will change status to SENT when complete)
    if not data.scheduled_at:
        send_notification_task.delay(
            notification.id,
            triggered_by_user_id=current_user.id,
            triggered_by_email=current_user.email,
        )

    return notification


@notifications_router.post("/{notification_id}/send", response_model=NotificationResponse)
async def send_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager),
    request: Request = None,
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

    # Pass auth context to Celery task for audit trail
    send_notification_task.delay(
        notification_id,
        triggered_by_user_id=current_user.id,
        triggered_by_email=current_user.email,
    )

    # Record this dispatch for rate limiting
    await record_notification_dispatch(current_user.id)

    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="send_notification",
        resource_type="notification",
        resource_id=notification_id,
        request=request,
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

    Access Control:
        - Manager and Admin roles: Can see all notifications
        - Viewer role: Can only see notifications where they are recipients
    
    Args:
        notification_id: ID of the notification
        channel: Filter by delivery channel (sms, email, voice, web)
        status: Filter by delivery status (pending, sent, delivered, failed, bounced)
        limit: Maximum number of results (1-1000, default 100)
        offset: Number of results to skip (default 0)
    """
    # Fetch the notification first to check permissions
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    # Viewer-role users can only see delivery logs for notifications where they are recipients
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
                detail="Access denied. You can only view delivery logs for notifications where you are a recipient."
            )

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

    Access Control:
        - Manager and Admin roles: Can see all responses
        - Viewer role: Can only see responses for notifications where they are recipients
    
    Args:
        notification_id: ID of the notification
        limit: Maximum number of results (1-1000, default 100)
        offset: Number of results to skip (default 0)
    """
    # Fetch the notification first to check permissions
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    # Viewer-role users can only see responses for notifications where they are recipients
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
                detail="Access denied. You can only view responses for notifications where you are a recipient."
            )

    query = db.query(NRModel).filter(NRModel.notification_id == notification_id)
    responses = query.all()
    result = []
    for r in responses:
        result.append(NotificationResponseOut(
            id=r.id,
            notification_id=r.notification_id,
            user_id=r.user_id,
            user_email=r.user_email,
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
async def submit_response(
    notification_id: int,
    data: NotificationResponseCreate,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Employee submits their safety response via the web portal.
    
    Two modes:
    1. Authenticated: Logged-in user responding to their own notification (Authorization header)
    2. Token-based: User clicking link from email/SMS (JWT token query param, no auth header)
    """
    from app.utils.checkin_link import verify_checkin_token
    from fastapi.security import HTTPBearer
    
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    # Determine user from token or current_user
    user_id = None
    user_email = None
    
    if token:
        # Token-based authentication (from email/SMS link) - NO CSRF REQUIRED
        payload = verify_checkin_token(token)
        if not payload:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        
        # Verify token matches notification
        if payload.get('notification_id') != notification_id:
            raise HTTPException(status_code=400, detail="Token does not match this notification")
        
        user_id = payload.get('user_id')
        
        # SECURITY: Check if user already responded via token
        # Token links are SINGLE-USE only - prevent response manipulation
        existing_response = db.query(NRModel).filter(
            NRModel.notification_id == notification_id,
            NRModel.user_id == user_id
        ).first()
        
        if existing_response:
            raise HTTPException(
                status_code=400, 
                detail="You have already submitted your safety response. Contact administrator if you need to change it."
            )
        
        # Get user email for the response record
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user_email = user.email
        else:
            user_email = None
    else:
        # Try to get authenticated user (requires Authorization header + CSRF token)
        # Use Security with HTTPBearer - will raise if no auth header
        bearer = HTTPBearer(auto_error=False)
        credentials = await bearer(request)
        
        if not credentials:
            raise HTTPException(
                status_code=401, 
                detail="Authentication required - provide JWT token (from email/SMS link) or log in"
            )
        
        # Manually get user from token
        from app.core.security import decode_token
        payload = decode_token(credentials.credentials, token_type="access")
        if not payload or payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = payload.get("sub")
        # Check is_enabled (account status) NOT is_online (presence)
        user = db.query(User).filter(User.id == int(user_id), User.is_enabled == True).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found or account disabled")
        
        user_id = user.id
        user_email = user.email

    # Use database row-level locking to prevent race conditions
    # Lock the notification row to prevent concurrent response creation
    from sqlalchemy import select, func
    
    # Use a transaction with proper locking for race condition prevention
    try:
        # Check if user already responded using row-level locking (SELECT FOR UPDATE)
        # This prevents two concurrent requests from both seeing "no response" and creating duplicates
        stmt = (
            select(NRModel)
            .where(NRModel.notification_id == notification_id)
            .where(NRModel.user_id == user_id)
            .with_for_update()  # Acquire exclusive lock on matching rows
        )
        existing_response = db.execute(stmt).scalar_one_or_none()

        if existing_response:
            # Update existing response
            existing_response.response_type = data.response_type
            existing_response.message = data.message
            existing_response.latitude = data.latitude
            existing_response.longitude = data.longitude
            existing_response.responded_at = datetime.now(timezone.utc)
            response = existing_response
        else:
            # Create new response (no duplicate possible due to lock)
            response = NRModel(
                notification_id=notification_id,
                user_id=user_id,
                user_email=user_email,
                channel=AlertChannel.WEB,
                response_type=data.response_type,
                message=data.message,
                latitude=data.latitude,
                longitude=data.longitude
            )
            db.add(response)

        # Create delivery log entry to track web delivery (mark as delivered when user responds)
        # Use locking here too to prevent duplicate delivery logs
        stmt_log = (
            select(DeliveryLog)
            .where(DeliveryLog.notification_id == notification_id)
            .where(DeliveryLog.user_id == user_id)
            .where(DeliveryLog.channel == AlertChannel.WEB)
            .with_for_update()
        )
        existing_log = db.execute(stmt_log).scalar_one_or_none()

        if not existing_log:
            delivery_log = DeliveryLog(
                notification_id=notification_id,
                user_id=user_id,
                user_email=user_email,
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
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating notification response: {e}")
        raise HTTPException(status_code=500, detail="Failed to record response")


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
    """Get response statistics counting unique users only (not duplicate responses)."""
    from sqlalchemy import distinct, func
    
    # Count unique users per response type (not total responses)
    safe_count = db.query(func.count(distinct(NRModel.user_id))).filter(
        NRModel.notification_id == notification_id,
        NRModel.response_type == 'safe'
    ).scalar() or 0
    
    need_help_count = db.query(func.count(distinct(NRModel.user_id))).filter(
        NRModel.notification_id == notification_id,
        NRModel.response_type == 'need_help'
    ).scalar() or 0
    
    acknowledged_count = db.query(func.count(distinct(NRModel.user_id))).filter(
        NRModel.notification_id == notification_id,
        NRModel.response_type == 'acknowledged'
    ).scalar() or 0
    
    # Total unique responders
    total_unique = db.query(func.count(distinct(NRModel.user_id))).filter(
        NRModel.notification_id == notification_id
    ).scalar() or 0
    
    return {
        "total": total_unique,
        "safe": safe_count,
        "need_help": need_help_count,
        "acknowledged": acknowledged_count
    }
