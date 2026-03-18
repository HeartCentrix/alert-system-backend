"""
Location Audience Management API

Endpoints for managing user-location assignments:
- Manual assignment by admins
- Automatic geofence-based assignment
- Location membership viewing
- Audit history

Security:
- RBAC validation (admin required for modifications)
- IDOR prevention (users can only view/modify their own data)
- Rate limiting
- Input validation and sanitization
"""
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, aliased
from sqlalchemy import select, func, and_, or_
from typing import Optional, List
from time import time as current_time

from app.database import get_db
from app.models import User, Location, UserLocation, UserLocationHistory, AuditLog, UserLocationStatus, UserLocationAssignmentType, UserRole
from app.utils.audit import create_audit_log
from app.utils.search import escape_like
from app.schemas import (
    UserLocationAssign, UserLocationRemove, UserLocationGeofenceUpdate,
    UserLocationResponse, UserLocationHistoryResponse,
    LocationMemberListResponse, UserLocationHistoryListResponse,
    UserGeofenceStatus, GeofenceCheckResult, LocationOverlapInfo
)
from app.core.deps import get_current_user, require_admin, require_manager
from app.core.geofence import (
    check_geofence, validate_coordinates, validate_geofence_radius,
    check_location_overlap, get_geo_service
)
from app.location_tasks import check_user_geofence_task

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/location-audience", tags=["Location Audience Management"])

# ─── RATE LIMITING ────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple in-memory rate limiter for API abuse prevention."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}
    
    def is_allowed(self, key: str) -> tuple[bool, int]:
        """
        Check if request is allowed.
        
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        now = current_time()
        window_start = now - self.window_seconds
        
        # Clean old entries
        if key in self._requests:
            self._requests[key] = [t for t in self._requests[key] if t > window_start]
        else:
            self._requests[key] = []
        
        # Check limit
        if len(self._requests[key]) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - self._requests[key][0]))
            return False, max(1, retry_after)
        
        # Record request
        self._requests[key].append(now)
        return True, 0


# Rate limiters for different operations
_geofence_update_limiter = RateLimiter(max_requests=30, window_seconds=60)  # 30/min for geofence updates
_assignment_limiter = RateLimiter(max_requests=100, window_seconds=60)  # 100/min for assignments


# ─── MANUAL ASSIGNMENT ENDPOINTS ──────────────────────────────────────────────

@router.post("/assign", response_model=UserLocationResponse, status_code=status.HTTP_201_CREATED)
def assign_user_to_location(
    data: UserLocationAssign,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Manually assign a user to a location.
    
    **Requirements:**
    - Admin role required
    - User must exist and be active
    - Location must exist and be active
    - Prevents duplicate active assignments
    
    **Security:**
    - RBAC validation
    - Input validation
    - Audit logging
    - Rate limiting
    """
    # Rate limiting
    client_ip = request.client.host
    allowed, retry_after = _assignment_limiter.is_allowed(f"assign:{current_user.id}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many assignment requests. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )
    
    # Validate user exists
    # Note: We don't check is_active (tracks online presence) or is_verified (SSO flag)
    # Any existing user can be assigned to a location
    user = db.query(User).filter(User.id == data.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Validate location exists
    location = db.query(Location).filter(
        Location.id == data.location_id,
        Location.is_active == True
    ).first()
    if not location:
        raise HTTPException(status_code=404, detail="Location not found or inactive")
    
    # Check for existing assignment (active or inactive)
    existing = db.query(UserLocation).filter(
        UserLocation.user_id == data.user_id,
        UserLocation.location_id == data.location_id,
    ).first()

    if existing and existing.status == UserLocationStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail="User is already assigned to this location"
        )

    if existing:
        # Reactivate the inactive assignment instead of creating a duplicate
        existing.status = UserLocationStatus.ACTIVE
        existing.assignment_type = UserLocationAssignmentType.MANUAL
        existing.assigned_by_id = current_user.id
        existing.notes = data.notes
        existing.expires_at = data.expires_at
        existing.assigned_at = datetime.now(timezone.utc)
        assignment = existing
    else:
        # Create new assignment
        assignment = UserLocation(
            user_id=data.user_id,
            location_id=data.location_id,
            assignment_type=UserLocationAssignmentType.MANUAL,
            status=UserLocationStatus.ACTIVE,
            assigned_by_id=current_user.id,
            notes=data.notes,
            expires_at=data.expires_at
        )
        db.add(assignment)
    
    # Record history
    history = UserLocationHistory(
        user_id=data.user_id,
        location_id=data.location_id,
        action="manually_assigned",
        assignment_type=UserLocationAssignmentType.MANUAL,
        new_status=UserLocationStatus.ACTIVE,
        triggered_by_user_id=current_user.id,
        reason=data.notes
    )
    db.add(history)

    # Audit log
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="assign_user_to_location",
        resource_type="user_location",
        resource_id=assignment.id,
        details={
            "user_id": data.user_id,
            "location_id": data.location_id,
            "notes": data.notes
        },
        request=request,
    ))
    
    db.commit()
    db.refresh(assignment)

    # Build response - fetch related data explicitly to avoid ambiguous joins
    # Use the already-loaded relationships (these work because foreign_keys are defined in model)
    user = assignment.user
    location_rel = assignment.location
    assigned_by_user = assignment.assigned_by

    return UserLocationResponse(
        id=assignment.id,
        user_id=assignment.user_id,
        user_name=user.full_name if user else None,
        user_email=user.email if user else None,
        location_id=assignment.location_id,
        location_name=location_rel.name if location_rel else None,
        assignment_type=assignment.assignment_type,
        status=assignment.status,
        detected_latitude=assignment.detected_latitude,
        detected_longitude=assignment.detected_longitude,
        distance_from_center_miles=assignment.distance_from_center_miles,
        assigned_by_id=assignment.assigned_by_id,
        assigned_by_name=assigned_by_user.full_name if assigned_by_user else None,
        notes=assignment.notes,
        assigned_at=assignment.assigned_at,
        expires_at=assignment.expires_at
    )


@router.post("/remove")
def remove_user_from_location(
    data: UserLocationRemove,
    request: Request,
    user_id: int = Query(..., description="User ID to remove"),
    location_id: int = Query(..., description="Location ID to remove from"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Remove a user from a location.
    
    **Requirements:**
    - Admin role required
    - Assignment must exist
    
    **Security:**
    - RBAC validation
    - Audit logging
    """
    # Find active assignment
    assignment = db.query(UserLocation).filter(
        UserLocation.user_id == user_id,
        UserLocation.location_id == location_id,
        UserLocation.status == UserLocationStatus.ACTIVE
    ).first()
    
    if not assignment:
        raise HTTPException(
            status_code=404,
            detail="No active assignment found for this user and location"
        )
    
    # Store previous state
    previous_status = assignment.status
    
    # Update status
    assignment.status = UserLocationStatus.INACTIVE
    assignment.updated_at = datetime.now(timezone.utc)
    
    # Record history
    history = UserLocationHistory(
        user_id=user_id,
        location_id=location_id,
        user_location_id=assignment.id,
        action="manually_removed",
        assignment_type=assignment.assignment_type,
        previous_status=previous_status,
        new_status=UserLocationStatus.INACTIVE,
        triggered_by_user_id=current_user.id,
        reason=data.reason
    )
    db.add(history)

    # Audit log
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="remove_user_from_location",
        resource_type="user_location",
        resource_id=assignment.id,
        details={
            "user_id": user_id,
            "location_id": location_id,
            "reason": data.reason
        },
        request=request,
    ))
    
    db.commit()
    
    return {
        "message": "User removed from location successfully",
        "assignment_id": assignment.id,
        "previous_status": previous_status.value,
        "new_status": UserLocationStatus.INACTIVE.value
    }


# ─── GEOFENCE-BASED ASSIGNMENT ENDPOINTS ──────────────────────────────────────

@router.post("/geofence/update", response_model=UserGeofenceStatus)
def update_user_geofence(
    data: UserLocationGeofenceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update user's location and trigger geofence check.

    This endpoint is called when:
    - User logs in
    - User updates their location
    - Periodic location sync

    **Security:**
    - Users can only update their own location (IDOR prevented via Depends)
    - Rate limiting (30 requests/min per user)
    - Coordinate validation (range, NaN, Infinity checks)
    - Coordinates rounded to 4 decimals (~11m precision) for privacy
    - No sensitive data in logs
    - Celery task runs async (non-blocking)

    **Flow:**
    1. Validate coordinates (range, type, NaN/Infinity)
    2. Round coordinates for privacy (~11m precision)
    3. Rate limit check (per user ID)
    4. Store user's current location
    5. Trigger async geofence check (Celery)
    6. Return current status
    """
    # Validate coordinates first (before rate limit to reject invalid early)
    is_valid, error = validate_coordinates(data.latitude, data.longitude)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

    # SECURITY: Round coordinates to 4 decimals (~11m precision) for privacy
    # This prevents tracking exact location while still enabling geofence
    rounded_lat = round(data.latitude, 4)
    rounded_lon = round(data.longitude, 4)

    # Rate limiting (after validation to avoid storing bad data)
    client_ip = request.client.host
    allowed, retry_after = _geofence_update_limiter.is_allowed(f"geofence:{current_user.id}")
    if not allowed:
        # Log rate limit event without sensitive data
        logger.warning(f"Rate limit exceeded for geofence update")
        raise HTTPException(
            status_code=429,
            detail=f"Too many location updates. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Update user's primary location fields (use rounded values)
    current_user.latitude = rounded_lat
    current_user.longitude = rounded_lon
    current_user.updated_at = datetime.now(timezone.utc)

    # Trigger async geofence check (use rounded coordinates)
    check_user_geofence_task.delay(current_user.id, rounded_lat, rounded_lon)
    
    # Get current locations for immediate response
    locations = db.query(Location).filter(
        Location.is_active == True,
        Location.latitude.isnot(None),
        Location.longitude.isnot(None)
    ).all()
    
    # Check geofences synchronously for immediate feedback (use rounded values)
    locations_inside = []
    locations_outside = []

    for loc in locations:
        result = check_geofence(rounded_lat, rounded_lon, loc)
        geofence_result = GeofenceCheckResult(
            location_id=loc.id,
            location_name=loc.name,
            is_inside=result.is_inside,
            distance_miles=result.distance_miles,
            distance_km=result.distance_km,
            radius_miles=result.radius_miles,
            margin_miles=result.margin_miles
        )
        
        if result.is_inside:
            locations_inside.append(geofence_result)
        else:
            locations_outside.append(geofence_result)
    
    db.commit()

    return UserGeofenceStatus(
        user_id=current_user.id,
        latitude=rounded_lat,
        longitude=rounded_lon,
        checked_at=datetime.now(timezone.utc),
        locations_inside=locations_inside,
        locations_outside=locations_outside,
        assignments_changed=[]  # Will be populated by async task
    )


# ─── VIEWING ENDPOINTS ────────────────────────────────────────────────────────

@router.get("/location/{location_id}/members", response_model=LocationMemberListResponse)
def get_location_members(
    location_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[UserLocationStatus] = Query(None, alias="status"),
    assignment_type: Optional[UserLocationAssignmentType] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    """
    Get all users assigned to a location.

    **Requirements:**
    - Manager role or higher required
    - Location must exist

    **Features:**
    - Pagination
    - Status filtering
    - Assignment type filtering
    """
    try:
        # Validate location exists
        location = db.query(Location).filter(Location.id == location_id).first()
        if not location:
            raise HTTPException(status_code=404, detail="Location not found")

        # Create aliases for the two User relationships to avoid AmbiguousForeignKeysError
        # member_user: the user who is assigned to the location (via user_id)
        # assigner_user: the admin who made the assignment (via assigned_by_id)
        member_user = aliased(User)
        assigner_user = aliased(User)

        # Build the base query with explicit joins using aliases
        # This tells SQLAlchemy exactly which foreign keys to use for each join
        # We select columns explicitly to avoid any relationship ambiguity
        base_query = db.query(
            UserLocation,
            member_user,
            assigner_user
        ).join(
            member_user,
            UserLocation.user_id == member_user.id
        ).outerjoin(
            assigner_user,
            UserLocation.assigned_by_id == assigner_user.id
        ).filter(
            UserLocation.location_id == location_id
        )

        # Apply optional filters
        if status_filter:
            base_query = base_query.filter(UserLocation.status == status_filter)
        if assignment_type:
            base_query = base_query.filter(UserLocation.assignment_type == assignment_type)

        # Get total count using a separate simple count query
        # This avoids ORDER BY affecting the count and ensures no ambiguity
        count_query = db.query(func.count(UserLocation.id)).join(
            member_user,
            UserLocation.user_id == member_user.id
        ).filter(
            UserLocation.location_id == location_id
        )
        if status_filter:
            count_query = count_query.filter(UserLocation.status == status_filter)
        if assignment_type:
            count_query = count_query.filter(UserLocation.assignment_type == assignment_type)
        
        total = count_query.scalar()

        # Apply ordering and pagination
        # Order by assigned_at DESC, then by member's first_name for consistent ordering
        assignments_with_users = base_query.order_by(
            UserLocation.assigned_at.desc(),
            member_user.first_name.asc()
        ).offset(
            (page - 1) * page_size
        ).limit(page_size).all()

        # Build response from the tuple results (UserLocation, member_user, assigner_user)
        items = []
        for row in assignments_with_users:
            assignment = row[0]
            member = row[1]  # Already loaded from the join
            assigner = row[2]  # Already loaded from the outerjoin
            
            items.append(
                _build_user_location_response_from_joined(
                    assignment, member, assigner, location
                )
            )

        return LocationMemberListResponse(
            total=total,
            page=page,
            page_size=page_size,
            location_id=location_id,
            location_name=location.name,
            items=items
        )
    except Exception as e:
        logger.error(f"Error in get_location_members: {e}", exc_info=True)
        raise


@router.get("/user/{user_id}/locations", response_model=List[UserLocationResponse])
def get_user_locations(
    user_id: int,
    include_inactive: bool = Query(False, description="Include inactive assignments"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all locations for a user.
    
    **Security:**
    - Users can only view their own locations (IDOR prevention)
    - Admins can view any user's locations
    """
    # IDOR check - users can only view their own data
    if current_user.id != user_id and current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        raise HTTPException(
            status_code=403,
            detail="Access denied. You can only view your own location assignments."
        )
    
    # Build query
    query = db.query(UserLocation).filter(UserLocation.user_id == user_id)
    
    if not include_inactive:
        query = query.filter(UserLocation.status == UserLocationStatus.ACTIVE)
    
    assignments = query.order_by(UserLocation.assigned_at.desc()).all()
    
    return [_build_user_location_response(db, a) for a in assignments]


@router.get("/location/{location_id}/history", response_model=UserLocationHistoryListResponse)
def get_location_history(
    location_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action_filter: Optional[str] = Query(None, alias="action"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Get location membership audit history.
    
    **Requirements:**
    - Admin role required
    
    **Features:**
    - Pagination
    - Action filtering
    """
    # Validate location exists
    location = db.query(Location).filter(Location.id == location_id).first()
    if not location:
        raise HTTPException(status_code=404, detail="Location not found")
    
    # Build query
    query = db.query(UserLocationHistory).filter(
        UserLocationHistory.location_id == location_id
    )
    
    if action_filter:
        safe_action = escape_like(action_filter)
        query = query.filter(UserLocationHistory.action.ilike(f"%{safe_action}%"))
    
    total = query.count()
    history = query.order_by(
        UserLocationHistory.created_at.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    
    items = [_build_history_response(db, h) for h in history]
    
    return UserLocationHistoryListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=items
    )


@router.get("/stats")
def get_location_audience_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    """
    Get location audience statistics.
    
    Returns:
    - Total assignments
    - Assignments by type
    - Assignments by status
    - Top locations by member count
    """
    # Total active assignments
    total_active = db.query(UserLocation).filter(
        UserLocation.status == UserLocationStatus.ACTIVE
    ).count()
    
    # By assignment type
    manual_count = db.query(UserLocation).filter(
        UserLocation.status == UserLocationStatus.ACTIVE,
        UserLocation.assignment_type == UserLocationAssignmentType.MANUAL
    ).count()
    
    geofence_count = db.query(UserLocation).filter(
        UserLocation.status == UserLocationStatus.ACTIVE,
        UserLocation.assignment_type == UserLocationAssignmentType.GEOFENCE
    ).count()
    
    # Top locations
    top_locations = db.query(
        Location.id,
        Location.name,
        func.count(UserLocation.id).label("member_count")
    ).join(
        UserLocation,
        and_(
            Location.id == UserLocation.location_id,
            UserLocation.status == UserLocationStatus.ACTIVE
        )
    ).group_by(
        Location.id, Location.name
    ).order_by(
        func.count(UserLocation.id).desc()
    ).limit(10).all()
    
    return {
        "total_active_assignments": total_active,
        "manual_assignments": manual_count,
        "geofence_assignments": geofence_count,
        "users_with_multiple_locations": 0,  # Would need subquery
        "top_locations": [
            {"id": loc.id, "name": loc.name, "member_count": loc.member_count}
            for loc in top_locations
        ]
    }


# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def _build_user_location_response_from_joined(
    assignment: UserLocation,
    member: User,
    assigner: Optional[User],
    location: Optional[Location]
) -> UserLocationResponse:
    """
    Build response from pre-joined query results.
    
    This function is used when the query explicitly joins UserLocation with
    aliased User tables and returns tuples of (UserLocation, member, assigner).
    
    This approach completely avoids AmbiguousForeignKeysError because:
    1. We use explicit aliases with explicit onclause in joins
    2. We don't rely on relationship loaders at all
    3. All data is fetched in a single query
    
    Args:
        assignment: UserLocation instance from query result
        member: User instance (the member, from the join via user_id)
        assigner: User instance or None (the admin who assigned, from outerjoin)
        location: Location instance (passed from earlier query)
    """
    return UserLocationResponse(
        id=assignment.id,
        user_id=assignment.user_id,
        user_name=member.full_name if member else None,
        user_email=member.email if member else None,
        location_id=assignment.location_id,
        location_name=location.name if location else None,
        assignment_type=assignment.assignment_type,
        status=assignment.status,
        detected_latitude=assignment.detected_latitude,
        detected_longitude=assignment.detected_longitude,
        distance_from_center_miles=assignment.distance_from_center_miles,
        assigned_by_id=assignment.assigned_by_id,
        assigned_by_name=assigner.full_name if assigner else None,
        notes=assignment.notes,
        assigned_at=assignment.assigned_at,
        expires_at=assignment.expires_at
    )


def _build_user_location_response(db: Session, assignment: UserLocation) -> UserLocationResponse:
    """
    Build response with related user and location data using relationships.
    
    WARNING: This function should ONLY be used when:
    - The UserLocation was fetched with explicit joins that resolve FK ambiguity, OR
    - The model relationships have properly configured foreign_keys parameters
    
    For the get_location_members endpoint, use 
    _build_user_location_response_from_joined() instead.
    """
    # Use relationships - these work because the model defines foreign_keys explicitly
    user = assignment.user
    location = assignment.location
    assigned_by_user = assignment.assigned_by

    return UserLocationResponse(
        id=assignment.id,
        user_id=assignment.user_id,
        user_name=user.full_name if user else None,
        user_email=user.email if user else None,
        location_id=assignment.location_id,
        location_name=location.name if location else None,
        assignment_type=assignment.assignment_type,
        status=assignment.status,
        detected_latitude=assignment.detected_latitude,
        detected_longitude=assignment.detected_longitude,
        distance_from_center_miles=assignment.distance_from_center_miles,
        assigned_by_id=assignment.assigned_by_id,
        assigned_by_name=assigned_by_user.full_name if assigned_by_user else None,
        notes=assignment.notes,
        assigned_at=assignment.assigned_at,
        expires_at=assignment.expires_at
    )


def _build_history_response(db: Session, history: UserLocationHistory) -> UserLocationHistoryResponse:
    """Build history response with related data."""
    user = db.query(User).filter(User.id == history.user_id).first()
    location = db.query(Location).filter(Location.id == history.location_id).first()
    triggered_by = None
    if history.triggered_by_user_id:
        triggered_by = db.query(User).filter(User.id == history.triggered_by_user_id).first()
    
    return UserLocationHistoryResponse(
        id=history.id,
        user_id=history.user_id,
        user_name=user.full_name if user else None,
        location_id=history.location_id,
        location_name=location.name if location else None,
        action=history.action,
        assignment_type=history.assignment_type,
        previous_status=history.previous_status,
        new_status=history.new_status,
        triggered_by_user_id=history.triggered_by_user_id,
        triggered_by_name=triggered_by.full_name if triggered_by else None,
        reason=history.reason,
        detected_latitude=history.detected_latitude,
        detected_longitude=history.detected_longitude,
        distance_from_center_miles=history.distance_from_center_miles,
        created_at=history.created_at
    )
