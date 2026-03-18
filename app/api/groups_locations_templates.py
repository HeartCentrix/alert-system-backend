import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List
from app.database import get_db
from app.models import Group, GroupType, Location, NotificationTemplate, User, AuditLog, UserLocation, UserLocationStatus, UserRole
from app.utils.audit import create_audit_log
from app.utils.search import escape_like
from app.schemas import (
    GroupCreate, GroupUpdate, GroupResponse, GroupDetailResponse, GroupMemberAdd,
    LocationCreate, LocationUpdate, LocationResponse,
    TemplateCreate, TemplateUpdate, TemplateResponse
)
from app.core.deps import get_current_user, require_admin, require_manager

logger = logging.getLogger(__name__)

# ─── GROUPS ───────────────────────────────────────────────────────────────────

groups_router = APIRouter(prefix="/groups", tags=["Groups"])


@groups_router.get("", response_model=List[GroupResponse])
def list_groups(
    search: Optional[str] = None,
    type: Optional[GroupType] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Group).filter(Group.is_active == True)
    
    # Filter groups based on user role:
    # - Admin/Super Admin: see all groups
    # - Manager: see only groups they are members of
    # - Viewer: see only groups they are members of
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        query = query.join(Group.members).filter(User.id == current_user.id)
    
    if search:
        safe_search = escape_like(search)
        query = query.filter(Group.name.ilike(f"%{safe_search}%"))
    if type:
        query = query.filter(Group.type == type)
    groups = query.order_by(Group.name).all()
    result = []
    for g in groups:
        r = GroupResponse(
            id=g.id, name=g.name, description=g.description,
            type=g.type, location_id=g.location_id,
            dynamic_filter=g.dynamic_filter, is_active=g.is_active,
            member_count=len(g.members), created_at=g.created_at
        )
        result.append(r)
    return result


@groups_router.post("", response_model=GroupResponse, status_code=201)
def create_group(
    data: GroupCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    request: Request = None,
):
    group = Group(
        name=data.name,
        description=data.description,
        type=data.type,
        location_id=data.location_id,
        dynamic_filter=data.dynamic_filter,
        created_by_id=current_user.id
    )

    # For dynamic groups, auto-populate members based on dynamic_filter
    # Use is_enabled (account status) NOT is_online (presence)
    if data.type == GroupType.DYNAMIC and data.dynamic_filter:
        query = db.query(User).filter(User.is_enabled == True)
        f = data.dynamic_filter
        # Apply filters only if they have non-empty, non-whitespace values
        if f.get("department") and str(f["department"]).strip():
            query = query.filter(User.department == f["department"].strip())
        if f.get("title") and str(f["title"]).strip():
            query = query.filter(User.title == f["title"].strip())
        if f.get("role") and str(f["role"]).strip():
            query = query.filter(User.role == f["role"].strip())
        if f.get("location_id") and str(f["location_id"]).strip():
            query = query.filter(User.location_id == f["location_id"])
        members = query.all()
        group.members = members
    elif data.member_ids:
        # For static groups, use provided member_ids
        members = db.query(User).filter(User.id.in_(data.member_ids)).all()
        group.members = members

    db.add(group)
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="create_group",
        resource_type="group",
        details={
            "group_name": group.name,
            "group_type": data.type.value,
            "member_count": len(group.members)
        },
        request=request,
    ))
    db.commit()
    db.refresh(group)
    return GroupResponse(
        id=group.id, name=group.name, description=group.description,
        type=group.type, location_id=group.location_id,
        dynamic_filter=group.dynamic_filter, is_active=group.is_active,
        member_count=len(group.members), created_at=group.created_at
    )


@groups_router.get("/{group_id}", response_model=GroupDetailResponse)
def get_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Check both existence AND active status (prevent access to soft-deleted groups)
    group = db.query(Group).filter(
        Group.id == group_id,
        Group.is_active == True
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Filter access based on user role:
    # - Admin/Super Admin: can view any group
    # - Manager/Viewer: can only view groups they are members of
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        if current_user not in group.members:
            raise HTTPException(
                status_code=403,
                detail="You can only view groups you are a member of"
            )
    
    return group


@groups_router.put("/{group_id}", response_model=GroupResponse)
def update_group(
    group_id: int,
    data: GroupUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check both existence AND active status (prevent modifying soft-deleted groups)
    group = db.query(Group).filter(
        Group.id == group_id,
        Group.is_active == True
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Handle member_ids separately (M2M relationship can't be set via setattr)
    member_ids = data.member_ids
    update_data = data.model_dump(exclude_unset=True, exclude={'member_ids'})

    # Update regular fields
    for field, value in update_data.items():
        setattr(group, field, value)

    # For dynamic groups, refresh members when dynamic_filter or type changes
    # Use is_enabled (account status) NOT is_online (presence)
    if group.type == GroupType.DYNAMIC and group.dynamic_filter:
        query = db.query(User).filter(User.is_enabled == True)
        f = group.dynamic_filter
        # Apply filters only if they have non-empty, non-whitespace values
        if f.get("department") and str(f["department"]).strip():
            query = query.filter(User.department == f["department"].strip())
        if f.get("title") and str(f["title"]).strip():
            query = query.filter(User.title == f["title"].strip())
        if f.get("role") and str(f["role"]).strip():
            query = query.filter(User.role == f["role"].strip())
        if f.get("location_id") and str(f["location_id"]).strip():
            query = query.filter(User.location_id == f["location_id"])
        members = query.all()
        group.members = members
    # Update members if provided (replace entire member list) - for static groups
    elif member_ids is not None:
        # Validate all user IDs exist
        valid_users = db.query(User).filter(
            User.id.in_(member_ids)
        ).all()
        valid_ids = {u.id for u in valid_users}
        invalid_ids = set(member_ids) - valid_ids

        if invalid_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid user IDs: {list(invalid_ids)}."
            )

        # Replace members list
        group.members = valid_users

    db.commit()
    db.refresh(group)
    return GroupResponse(
        id=group.id, name=group.name, description=group.description,
        type=group.type, location_id=group.location_id,
        dynamic_filter=group.dynamic_filter, is_active=group.is_active,
        member_count=len(group.members), created_at=group.created_at
    )


@groups_router.delete("/{group_id}")
def delete_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check both existence AND active status (can't delete what's already deleted)
    group = db.query(Group).filter(
        Group.id == group_id,
        Group.is_active == True
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    group.is_active = False
    db.commit()
    return {"message": "Group deleted"}


@groups_router.post("/{group_id}/members")
def add_members(
    group_id: int,
    data: GroupMemberAdd,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Managers can only add members to groups they are part of
    # Admin/Super Admin can add members to any group
    if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
        if current_user not in group.members:
            raise HTTPException(
                status_code=403,
                detail="You can only add members to groups you are a member of"
            )
    
    users = db.query(User).filter(User.id.in_(data.user_ids)).all()
    existing_ids = {m.id for m in group.members}
    for u in users:
        if u.id not in existing_ids:
            group.members.append(u)
    db.commit()
    return {"message": f"Added {len(users)} members", "total_members": len(group.members)}


@groups_router.delete("/{group_id}/members/{user_id}")
def remove_member(
    group_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check both existence AND active status (prevent modifying soft-deleted groups)
    group = db.query(Group).filter(
        Group.id == group_id,
        Group.is_active == True
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    user = db.query(User).filter(User.id == user_id).first()
    if user and user in group.members:
        group.members.remove(user)
        db.commit()
    return {"message": "Member removed"}


@groups_router.post("/preview")
def preview_dynamic_group(
    data: GroupCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Preview which users will be included in a dynamic group based on the filter criteria.
    
    This endpoint helps users see the matching members before creating a dynamic group.
    """
    if data.type != GroupType.DYNAMIC:
        raise HTTPException(
            status_code=400,
            detail="Preview is only available for dynamic groups"
        )
    
    if not data.dynamic_filter:
        raise HTTPException(
            status_code=400,
            detail="dynamic_filter is required for preview"
        )

    # Use is_enabled (account status) NOT is_online (presence)
    query = db.query(User).filter(User.is_enabled == True)
    f = data.dynamic_filter

    # Apply filters only if they have non-empty, non-whitespace values
    if f.get("department") and str(f["department"]).strip():
        query = query.filter(User.department == f["department"].strip())
    if f.get("title") and str(f["title"]).strip():
        query = query.filter(User.title == f["title"].strip())
    if f.get("role") and str(f["role"]).strip():
        query = query.filter(User.role == f["role"].strip())
    if f.get("location_id") and str(f["location_id"]).strip():
        query = query.filter(User.location_id == f["location_id"])
    
    members = query.all()
    
    return {
        "member_count": len(members),
        "members": [
            {
                "id": m.id,
                "email": m.email,
                "first_name": m.first_name,
                "last_name": m.last_name,
                "full_name": f"{m.first_name} {m.last_name}",
                "department": m.department,
                "title": m.title,
                "role": m.role.value if m.role else None
            }
            for m in members
        ]
    }


@groups_router.get("/filters/options")
def get_filter_options(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get unique values for dynamic group filter options.

    Returns unique departments, titles, and roles that can be used to create dynamic groups.
    """
    # Get unique departments (from all users, not just active)
    departments = db.query(User.department).filter(
        User.department.isnot(None)
    ).distinct().all()

    # Get unique titles (from all users, not just active)
    titles = db.query(User.title).filter(
        User.title.isnot(None)
    ).distinct().all()

    # Get all available roles
    roles = [role.value for role in UserRole]

    return {
        "departments": [d[0] for d in departments if d[0]],
        "titles": [t[0] for t in titles if t[0]],
        "roles": roles,
    }


# ─── LOCATIONS ────────────────────────────────────────────────────────────────

locations_router = APIRouter(prefix="/locations", tags=["Locations"])


@locations_router.get("", response_model=List[LocationResponse])
def list_locations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    locations = db.query(Location).filter(Location.is_active == True).order_by(Location.name).all()
    result = []
    for loc in locations:
        # Count users in user_locations table (many-to-many)
        user_count = db.query(UserLocation).filter(
            UserLocation.location_id == loc.id,
            UserLocation.status == UserLocationStatus.ACTIVE
        ).count()
        r = LocationResponse(
            id=loc.id, name=loc.name, address=loc.address,
            city=loc.city, state=loc.state, zip_code=loc.zip_code,
            country=loc.country, latitude=loc.latitude, longitude=loc.longitude,
            geofence_radius_miles=loc.geofence_radius_miles, is_active=loc.is_active,
            user_count=user_count, created_at=loc.created_at
        )
        result.append(r)
    return result


@locations_router.post("", response_model=LocationResponse, status_code=status.HTTP_201_CREATED)
def create_location(
    data: LocationCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Create a new location with geofence.
    
    Features:
    - Input validation and sanitization
    - Overlap detection with existing locations
    - Redis GEO index sync
    - Audit logging
    """
    from app.core.geofence import validate_location_input, check_location_overlap, get_geo_service
    
    # Validate and sanitize input
    validation = validate_location_input(
        name=data.name,
        latitude=data.latitude,
        longitude=data.longitude,
        radius_miles=data.geofence_radius_miles
    )
    
    if not validation["is_valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Validation failed",
                "errors": validation["errors"]
            }
        )
    
    # Check for overlaps with existing locations
    existing_locations = db.query(Location).filter(
        Location.is_active == True,
        Location.latitude.isnot(None),
        Location.longitude.isnot(None)
    ).all()
    
    overlaps = check_location_overlap(
        new_latitude=validation["sanitized"]["latitude"],
        new_longitude=validation["sanitized"]["longitude"],
        new_radius=validation["sanitized"]["geofence_radius_miles"],
        existing_locations=existing_locations
    )
    
    # Create location
    location = Location(
        name=validation["sanitized"]["name"],
        address=data.address,
        city=data.city,
        state=data.state,
        zip_code=data.zip_code,
        country=data.country,
        latitude=validation["sanitized"]["latitude"],
        longitude=validation["sanitized"]["longitude"],
        geofence_radius_miles=validation["sanitized"]["geofence_radius_miles"],
        is_active=True
    )
    db.add(location)

    # Audit log
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="create_location",
        resource_type="location",
        details={
            "name": location.name,
            "latitude": location.latitude,
            "longitude": location.longitude,
            "geofence_radius_miles": location.geofence_radius_miles,
            "overlaps": len(overlaps)
        },
        request=request,
    ))
    
    db.commit()
    db.refresh(location)
    
    # Sync to Redis GEO index (async)
    try:
        from app.location_tasks import sync_all_locations_to_redis
        sync_all_locations_to_redis.delay()
    except Exception as e:
        logger.warning(f"Failed to sync location to Redis: {e}")
    
    return LocationResponse(**{**location.__dict__, "user_count": 0})


@locations_router.put("/{location_id}", response_model=LocationResponse)
def update_location(
    location_id: int,
    data: LocationUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check both existence AND active status (prevent modifying soft-deleted locations)
    location = db.query(Location).filter(
        Location.id == location_id,
        Location.is_active == True
    ).first()
    """
    Update location with validation and Redis sync.
    
    Features:
    - Input validation for coordinates and radius
    - Overlap detection
    - Redis GEO index update
    - Audit logging
    """
    from app.core.geofence import validate_coordinates, validate_geofence_radius, check_location_overlap
    
    location = db.query(Location).filter(Location.id == location_id).first()
    if not location:
        raise HTTPException(status_code=404, detail="Location not found")
    
    # Validate coordinates if being updated
    new_latitude = data.latitude if data.latitude is not None else location.latitude
    new_longitude = data.longitude if data.longitude is not None else location.longitude
    new_radius = data.geofence_radius_miles if data.geofence_radius_miles is not None else location.geofence_radius_miles
    
    # Validate coordinates
    if data.latitude is not None or data.longitude is not None:
        if new_latitude is None or new_longitude is None:
            raise HTTPException(
                status_code=400,
                detail="Both latitude and longitude must be provided together"
            )
        is_valid, error = validate_coordinates(new_latitude, new_longitude)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)
    
    # Validate radius if being updated
    if data.geofence_radius_miles is not None:
        is_valid, error = validate_geofence_radius(new_radius)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)
    
    # Check for overlaps if coordinates or radius changed
    if (data.latitude is not None or data.longitude is not None or 
        data.geofence_radius_miles is not None):
        
        existing_locations = db.query(Location).filter(
            Location.is_active == True,
            Location.latitude.isnot(None),
            Location.longitude.isnot(None),
            Location.id != location_id  # Exclude self
        ).all()
        
        overlaps = check_location_overlap(
            new_latitude=new_latitude,
            new_longitude=new_longitude,
            new_radius=new_radius,
            existing_locations=existing_locations
        )
        
        if overlaps:
            # Log overlaps but don't prevent update - just warn
            logger.info(f"Location update overlaps with {len(overlaps)} locations")
    
    # Update fields
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(location, field, value)

    # Audit log
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="update_location",
        resource_type="location",
        resource_id=location_id,
        details={
            "updated_fields": list(update_data.keys()),
            "latitude": location.latitude,
            "longitude": location.longitude,
            "geofence_radius_miles": location.geofence_radius_miles
        },
        request=request,
    ))
    
    db.commit()
    db.refresh(location)
    
    # Sync to Redis GEO index
    try:
        from app.location_tasks import sync_all_locations_to_redis
        sync_all_locations_to_redis.delay()
    except Exception as e:
        logger.warning(f"Failed to sync location to Redis: {e}")
    
    # Count active assignments
    user_count = db.query(UserLocation).filter(
        UserLocation.location_id == location_id,
        UserLocation.status == UserLocationStatus.ACTIVE
    ).count()
    
    return LocationResponse(**{**location.__dict__, "user_count": user_count})


@locations_router.delete("/{location_id}")
def delete_location(
    location_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check both existence AND active status (can't delete what's already deleted)
    location = db.query(Location).filter(
        Location.id == location_id,
        Location.is_active == True
    ).first()
    if not location:
        raise HTTPException(status_code=404, detail="Location not found")
    location.is_active = False
    db.commit()
    return {"message": "Location deleted"}


# ─── TEMPLATES ────────────────────────────────────────────────────────────────

templates_router = APIRouter(prefix="/templates", tags=["Templates"])


@templates_router.get("", response_model=List[TemplateResponse])
def list_templates(
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(NotificationTemplate).filter(NotificationTemplate.is_active == True)
    if category:
        query = query.filter(NotificationTemplate.category == category)
    return query.order_by(NotificationTemplate.name).all()


@templates_router.post("", response_model=TemplateResponse, status_code=201)
def create_template(
    data: TemplateCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    template = NotificationTemplate(**data.model_dump(), created_by_id=current_user.id)
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


# IMPORTANT: /categories must be defined BEFORE /{template_id} to avoid route shadowing
# FastAPI matches routes in order, and /{template_id} would match "categories" as an ID
@templates_router.get("/categories")
def get_categories(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get all unique template categories."""
    results = db.query(NotificationTemplate.category).filter(
        NotificationTemplate.category != None,
        NotificationTemplate.is_active == True
    ).distinct().all()
    return [r[0] for r in results if r[0]]


@templates_router.put("/{template_id}", response_model=TemplateResponse)
def update_template(
    template_id: int,
    data: TemplateUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check both existence AND active status (prevent modifying soft-deleted templates)
    template = db.query(NotificationTemplate).filter(
        NotificationTemplate.id == template_id,
        NotificationTemplate.is_active == True
    ).first()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    # Use exclude_unset=True to allow clearing fields to None
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(template, field, value)
    db.commit()
    db.refresh(template)
    return template


@templates_router.delete("/{template_id}")
def delete_template(
    template_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check both existence AND active status (can't delete what's already deleted)
    template = db.query(NotificationTemplate).filter(
        NotificationTemplate.id == template_id,
        NotificationTemplate.is_active == True
    ).first()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    template.is_active = False
    db.commit()
    return {"message": "Template deleted"}
