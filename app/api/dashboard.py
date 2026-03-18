from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.models import (
    User, Group, Location, Notification, Incident,
    NotificationStatus, IncidentStatus, UserRole
)
from app.schemas import DashboardStats
from app.core.deps import get_current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

# Dashboard query limits
MAX_ACTIVITY_DAYS = 365  # Maximum days for activity queries


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)

    total_users = db.query(User).count()
    # Online users = users with recent heartbeat (is_online=True)
    online_users = db.query(User).filter(User.is_online == True).count()
    total_groups = db.query(Group).filter(Group.is_active == True).count()
    total_locations = db.query(Location).filter(Location.is_active == True).count()
    active_incidents = db.query(Incident).filter(Incident.status == IncidentStatus.ACTIVE).count()

    # Count notifications that were actually dispatched today
    # Include: SENT (completed), PARTIALLY_SENT (mixed results),
    #          SENDING (in progress), FAILED (attempted but failed)
    # Exclude: DRAFT (never sent), SCHEDULED (not yet sent)
    dispatched_statuses = [
        NotificationStatus.SENT,
        NotificationStatus.PARTIALLY_SENT,
        NotificationStatus.SENDING,
        NotificationStatus.FAILED
    ]

    notifications_today = db.query(Notification).filter(
        Notification.created_at >= today_start,
        Notification.status.in_(dispatched_statuses)
    ).count()

    notifications_week = db.query(Notification).filter(
        Notification.created_at >= week_start,
        Notification.status.in_(dispatched_statuses)
    ).count()

    # Get recent notifications - filter by role for security
    # Viewer-role users can only see notifications where they are recipients
    recent_query = db.query(Notification)
    if current_user.role == UserRole.VIEWER:
        recent_query = recent_query.filter(
            or_(
                Notification.target_all == True,
                Notification.target_users.any(User.id == current_user.id),
                Notification.target_groups.any(Group.members.any(User.id == current_user.id))
            )
        )
    
    recent_notifications = recent_query.order_by(
        desc(Notification.created_at)
    ).limit(5).all()

    recent_incidents = db.query(Incident).order_by(
        desc(Incident.created_at)
    ).limit(5).all()

    return {
        "total_users": total_users,
        "online_users": online_users,
        "total_groups": total_groups,
        "total_locations": total_locations,
        "active_incidents": active_incidents,
        "notifications_today": notifications_today,
        "notifications_this_week": notifications_week,
        "recent_notifications": recent_notifications,
        "recent_incidents": recent_incidents
    }


@router.get("/map-data")
def get_map_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Return location data with employee counts for the audience map.

    Access Control:
        - ALL users (including VIEWER): Can see ALL active locations
        - Location assignment only affects alert targeting, not map visibility
    """
    from app.models import UserLocation, UserLocationStatus

    # ALL users can see all active locations on the map
    # This is intentional for emergency alert systems - everyone needs visibility
    locations = db.query(Location).filter(Location.is_active == True).all()

    result = []
    for loc in locations:
        # Count users in user_locations table (many-to-many) for consistency
        user_count = db.query(UserLocation).filter(
            UserLocation.location_id == loc.id,
            UserLocation.status == UserLocationStatus.ACTIVE
        ).count()

        result.append({
            "id": loc.id,
            "name": loc.name,
            "address": loc.address,
            "city": loc.city,
            "state": loc.state,
            "latitude": loc.latitude,
            "longitude": loc.longitude,
            "geofence_radius_miles": loc.geofence_radius_miles,
            "user_count": user_count
        })

    # Also return users without a location (only for non-viewers)
    unassigned_count = 0
    if current_user.role != UserRole.VIEWER:
        # Count enabled users (not just online) without location assignment
        unassigned_count = db.query(User).filter(
            User.location_id == None,
            User.is_enabled == True
        ).count()

    return {
        "locations": result,
        "total_users": sum(l["user_count"] for l in result) + unassigned_count,
        "unassigned_users": unassigned_count
    }


@router.get("/notification-activity")
def get_notification_activity(
    days: int = 7,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Daily notification counts for the last N days.

    Args:
        days: Number of days to query (1-365, default 7)
    
    Access Control:
        - Viewer role: Can only see activity for notifications they received
        - Manager/Admin: Can see all notification activity
    """
    # Validate days parameter to prevent unbounded queries (DoS protection)
    if days < 1:
        raise HTTPException(
            status_code=400,
            detail="Days parameter must be at least 1"
        )
    if days > MAX_ACTIVITY_DAYS:
        raise HTTPException(
            status_code=400,
            detail=f"Days parameter cannot exceed {MAX_ACTIVITY_DAYS}"
        )

    from sqlalchemy import cast, Date
    start = datetime.now(timezone.utc) - timedelta(days=days)

    # Build query - filter by role for security
    query = db.query(
        func.date(Notification.created_at).label("date"),
        func.count(Notification.id).label("count")
    ).filter(
        Notification.created_at >= start
    )
    
    # Viewer-role users can only see activity for their own notifications
    if current_user.role == UserRole.VIEWER:
        query = query.filter(
            or_(
                Notification.target_all == True,
                Notification.target_users.any(User.id == current_user.id),
                Notification.target_groups.any(Group.members.any(User.id == current_user.id))
            )
        )

    results = query.group_by(
        func.date(Notification.created_at)
    ).order_by(
        func.date(Notification.created_at)
    ).all()

    return [{"date": str(r.date), "count": r.count} for r in results]
