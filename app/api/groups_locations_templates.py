from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional, List
from app.database import get_db
from app.models import Group, GroupType, Location, NotificationTemplate, User, AuditLog
from app.schemas import (
    GroupCreate, GroupUpdate, GroupResponse, GroupDetailResponse, GroupMemberAdd,
    LocationCreate, LocationUpdate, LocationResponse,
    TemplateCreate, TemplateUpdate, TemplateResponse
)
from app.core.deps import get_current_user, require_admin, require_manager

# ─── GROUPS ───────────────────────────────────────────────────────────────────

groups_router = APIRouter(prefix="/groups", tags=["Groups"])


@groups_router.get("", response_model=List[GroupResponse])
def list_groups(
    search: Optional[str] = None,
    type: Optional[GroupType] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    query = db.query(Group).filter(Group.is_active == True)
    if search:
        query = query.filter(Group.name.ilike(f"%{search}%"))
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
    current_user: User = Depends(require_admin)
):
    group = Group(
        name=data.name,
        description=data.description,
        type=data.type,
        location_id=data.location_id,
        dynamic_filter=data.dynamic_filter,
        created_by_id=current_user.id
    )
    if data.member_ids:
        members = db.query(User).filter(User.id.in_(data.member_ids)).all()
        group.members = members
    db.add(group)
    db.add(AuditLog(user_id=current_user.id, action="create_group", resource_type="group"))
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
    current_user: User = Depends(require_manager)
):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


@groups_router.put("/{group_id}", response_model=GroupResponse)
def update_group(
    group_id: int,
    data: GroupUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    # Use exclude_unset=True to allow clearing fields to None
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(group, field, value)
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
    group = db.query(Group).filter(Group.id == group_id).first()
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
    current_user: User = Depends(require_admin)
):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
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
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    user = db.query(User).filter(User.id == user_id).first()
    if user and user in group.members:
        group.members.remove(user)
        db.commit()
    return {"message": "Member removed"}


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
        user_count = db.query(User).filter(
            User.location_id == loc.id, User.is_active == True, User.deleted_at == None
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


@locations_router.post("", response_model=LocationResponse, status_code=201)
def create_location(
    data: LocationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    location = Location(**data.model_dump())
    db.add(location)
    db.commit()
    db.refresh(location)
    return LocationResponse(**{**location.__dict__, "user_count": 0})


@locations_router.put("/{location_id}", response_model=LocationResponse)
def update_location(
    location_id: int,
    data: LocationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    location = db.query(Location).filter(Location.id == location_id).first()
    if not location:
        raise HTTPException(status_code=404, detail="Location not found")
    # Use exclude_unset=True to allow clearing fields to None
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(location, field, value)
    db.commit()
    db.refresh(location)
    # Count only active, non-deleted users at this location
    user_count = db.query(User).filter(
        User.location_id == location_id,
        User.is_active == True,
        User.deleted_at == None
    ).count()
    return LocationResponse(**{**location.__dict__, "user_count": user_count})


@locations_router.delete("/{location_id}")
def delete_location(
    location_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    location = db.query(Location).filter(Location.id == location_id).first()
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


@templates_router.put("/{template_id}", response_model=TemplateResponse)
def update_template(
    template_id: int,
    data: TemplateUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    template = db.query(NotificationTemplate).filter(NotificationTemplate.id == template_id).first()
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
    template = db.query(NotificationTemplate).filter(NotificationTemplate.id == template_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    template.is_active = False
    db.commit()
    return {"message": "Template deleted"}


@templates_router.get("/categories")
def get_categories(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    results = db.query(NotificationTemplate.category).filter(
        NotificationTemplate.category != None,
        NotificationTemplate.is_active == True
    ).distinct().all()
    return [r[0] for r in results if r[0]]
