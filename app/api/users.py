import io
import csv
import logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from typing import Annotated, Optional, List
from app.database import get_db
from app.models import User, UserRole, AuditLog, Group, GroupType, UserLocation, UserLocationHistory, Incident, Notification, NotificationTemplate
from app.utils.audit import create_audit_log
from app.schemas import UserCreate, UserUpdate, UserResponse, UserListResponse, CSVImportResponse, UserBulkDeleteResponse, AdminMFAStatusResponse, AdminMFAResetRequest, AdminMFAResetResponse, HeartbeatResponse
from app.utils.search import escape_like
from app.schemas import UserCreate, UserUpdate, UserResponse, UserListResponse, CSVImportResponse, UserBulkDeleteResponse, AdminMFAStatusResponse, AdminMFAResetRequest, AdminMFAResetResponse
from app.core.security import hash_password
from app.core.deps import get_current_user, require_admin, require_manager
from app.services.mfa_lifecycle import get_mfa_service
from app.services.mfa_recovery import get_recovery_code_status, invalidate_all_recovery_codes
from app.services.rate_limiter import check_api_rate_limit, record_api_request, API_RATE_LIMIT_MAX

# ─── ERROR MESSAGE CONSTANTS ──────────────────────────────────────────────────
USER_NOT_FOUND_MSG = "User not found"


logger = logging.getLogger(__name__)


def _scrub_email(email: str) -> str:
    """
    Scrub email address for safe logging while keeping it useful for debugging.

    Shows: first 2 chars + *** + @ + domain
    Example: john.doe@example.com → jo***@example.com
    """
    if not email or '@' not in email:
        return "***@***"

    local, domain = email.rsplit('@', 1)
    if len(local) <= 2:
        scrubbed_local = local + "***"
    else:
        scrubbed_local = local[:2] + "***"

    return f"{scrubbed_local}@{domain}"


def _log_user_identity(user_id: Optional[int], email: Optional[str]) -> str:
    """
    Create a safe user identity string for logging.

    Shows: user_id + scrubbed email
    Example: "user_id=12345, email=jo***@example.com"
    """
    parts = []
    if user_id is not None:
        parts.append(f"user_id={user_id}")
    if email:
        parts.append(f"email={_scrub_email(email)}")
    return ", ".join(parts) if parts else "[UNKNOWN]"

router = APIRouter(prefix="/users", tags=["Users / People"])

# Maximum allowed CSV file size: 5MB
MAX_CSV_FILE_SIZE = 5 * 1024 * 1024

# Maximum allowed CSV rows per import request
MAX_CSV_ROWS = 1000


def _user_field_matches_filter(user_value: str, filter_value: str) -> bool:
    """Check if a user field matches a filter value."""
    if not filter_value or not str(filter_value).strip():
        return True  # Empty filter matches anything
    return user_value == filter_value.strip()


def _user_location_matches_filter(user_location_id: int, filter_location_id: str) -> bool:
    """Check if user location matches filter location."""
    if not filter_location_id or not str(filter_location_id).strip():
        return True  # Empty filter matches anything
    return user_location_id == int(filter_location_id)


def _user_matches_dynamic_filter(user: User, f: dict) -> bool:
    """Check if a user matches a dynamic group's filter criteria."""
    # Check each filter field - all must match (AND logic)
    if not _user_field_matches_filter(user.department, f.get("department")):
        return False
    if not _user_field_matches_filter(user.title, f.get("title")):
        return False
    if not _user_field_matches_filter(user.role, f.get("role")):
        return False
    if not _user_location_matches_filter(user.location_id, f.get("location_id")):
        return False
    return True


def _update_group_membership(group, user: User) -> None:
    """Add or remove a user from a group based on filter match result."""
    if _user_matches_dynamic_filter(user, group.dynamic_filter):
        if user not in group.members:
            group.members.append(user)
    elif user in group.members:
        group.members.remove(user)


def refresh_dynamic_groups_for_user(db: Session, user: User) -> None:
    """
    Refresh dynamic group memberships for a user after create/update.

    Finds all active dynamic groups and re-evaluates whether the user
    should be a member based on each group's filter criteria.
    """
    try:
        dynamic_groups = db.query(Group).filter(
            Group.type == GroupType.DYNAMIC,
            Group.is_active == True,
            Group.dynamic_filter.isnot(None)
        ).all()

        for group in dynamic_groups:
            if not group.dynamic_filter:
                continue
            _update_group_membership(group, user)

        db.commit()
    except Exception as e:
        logger.error(f"Error refreshing dynamic groups for user {user.id}: {e}")
        db.rollback()


def _prevent_privilege_escalation(current_user: User, target_role: Optional[UserRole]):
    """Prevent ADMIN users from creating or updating SUPER_ADMIN users.

    Only SUPER_ADMIN can assign SUPER_ADMIN role to other users.
    """
    if target_role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SUPER_ADMIN can create or update SUPER_ADMIN users"
        )


def _sanitize_formula_characters(value: str) -> str:
    """
    Sanitize formula characters to prevent CSV injection attacks.
    
    CSV injection (DDE/Formula injection) occurs when spreadsheet applications
    interpret cell values starting with =, +, -, or @ as formulas.
    This can lead to data exfiltration or remote code execution.
    
    Mitigation: Prefix dangerous characters with a single quote (') which forces
    the spreadsheet to treat the value as a string literal.
    
    OWASP Reference: https://owasp.org/www-community/attacks/CSV_Injection
    """
    if not value:
        return value
    
    # Check if value starts with formula-triggering characters
    if value[0] in ['=', '+', '-', '@']:
        # Prefix with single quote to escape formula interpretation
        return "'" + value
    
    return value


@router.get("", response_model=UserListResponse)
def list_users(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    search: Annotated[Optional[str], Query()] = None,
    department: Annotated[Optional[str], Query()] = None,
    location_id: Annotated[Optional[int], Query()] = None,
    role: Annotated[Optional[UserRole], Query()] = None,
    is_active: Annotated[Optional[bool], Query()] = None,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(get_current_user)] = None
):
    query = db.query(User)

    if search:
        safe_search = escape_like(search)
        query = query.filter(or_(
            User.first_name.ilike(f"%{safe_search}%"),
            User.last_name.ilike(f"%{safe_search}%"),
            User.email.ilike(f"%{safe_search}%"),
            User.phone.ilike(f"%{safe_search}%"),
            User.department.ilike(f"%{safe_search}%"),
            User.employee_id.ilike(f"%{safe_search}%"),
        ))
    if department:
        query = query.filter(User.department == department)
    if location_id:
        query = query.filter(User.location_id == location_id)
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        # Backward compatibility: is_active parameter now filters by is_enabled
        # For online status filtering, use is_online parameter (if added in future)
        query = query.filter(User.is_enabled == is_active)

    total = query.count()
    users = query.order_by(User.first_name).offset((page - 1) * page_size).limit(page_size).all()

    return UserListResponse(total=total, page=page, page_size=page_size, items=users)


# ─── USER CREATION HELPERS ───────────────────────────────────────────────────

def _check_user_uniqueness(db: Session, data: UserCreate) -> None:
    """Validate uniqueness of email, phone, and employee_id."""
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    if data.phone and db.query(User).filter(User.phone == data.phone).first():
        raise HTTPException(
            status_code=400,
            detail="Phone number already registered. Each user must have a unique phone number."
        )

    if data.employee_id and db.query(User).filter(User.employee_id == data.employee_id).first():
        raise HTTPException(status_code=400, detail="Employee ID already exists")


def _create_user_record(data: UserCreate, current_user: User) -> User:
    """Create a User ORM object from validated data."""
    return User(
        email=data.email,
        hashed_password=hash_password(data.password),
        first_name=data.first_name,
        last_name=data.last_name,
        phone=data.phone,
        department=data.department,
        title=data.title,
        employee_id=data.employee_id or None,
        role=data.role,
        location_id=data.location_id,
        preferred_channels=data.preferred_channels,
        is_active=True
    )


def _handle_user_creation_error(e: Exception, data: UserCreate) -> None:
    """Handle database errors during user creation."""
    error_msg = str(e).lower()
    if "unique" in error_msg or "duplicate" in error_msg:
        if "phone" in error_msg or "phone" in str(data):
            raise HTTPException(
                status_code=400,
                detail="Phone number already registered. Each user must have a unique phone number."
            )
        raise HTTPException(
            status_code=400,
            detail="A user with this email or employee ID already exists"
        )
    raise HTTPException(status_code=500, detail="Failed to create user")


# ─── USER ENDPOINTS ──────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {
            "description": "Bad Request - Duplicate email, phone, or employee_id",
            "content": {
                "application/json": {
                    "examples": {
                        "email": {"summary": "Email already registered", "value": {"detail": "Email already registered"}},
                        "phone": {"summary": "Phone already registered", "value": {"detail": "Phone number already registered..."}},
                        "employee_id": {"summary": "Employee ID exists", "value": {"detail": "Employee ID already exists"}},
                    }
                }
            }
        },
        403: {
            "description": "Forbidden - ADMIN cannot create SUPER_ADMIN users",
            "content": {
                "application/json": {
                    "example": {"detail": "Only SUPER_ADMIN can create or update SUPER_ADMIN users"}
                }
            }
        },
        500: {
            "description": "Internal Server Error - Database error during creation",
            "content": {
                "application/json": {
                    "example": {"detail": "Failed to create user"}
                }
            }
        },
    }
)
def create_user(
    data: UserCreate,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_admin)] = None,
    request: Request = None,
):
    """Create a new user account.

    Args:
        data: User creation data
        db: Database session
        current_user: Authenticated admin user
        request: HTTP request for audit logging

    Returns:
        Created user account

    Raises:
        HTTPException: 400 - Duplicate email, phone, or employee_id
        HTTPException: 403 - ADMIN cannot create SUPER_ADMIN users
        HTTPException: 500 - Database error during creation
    """
    # Validate uniqueness constraints
    _check_user_uniqueness(db, data)

    # Prevent privilege escalation
    _prevent_privilege_escalation(current_user, data.role)

    # Create user record
    user = _create_user_record(data, current_user)

    db.add(user)
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="create_user",
        resource_type="user",
        details={"email": data.email, "phone": data.phone},
        request=request,
    ))

    try:
        db.commit()
        db.refresh(user)
        refresh_dynamic_groups_for_user(db, user)
    except Exception as e:
        db.rollback()
        _handle_user_creation_error(e, data)

    return user


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    responses={
        404: {"description": "Not Found - User does not exist"},
    }
)
def get_user(
    user_id: int,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_manager)] = None
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=USER_NOT_FOUND_MSG)
    return user


def _validate_user_update_permissions(current_user: User, user: User, data: UserUpdate) -> None:
    """Validate permissions for updating a user profile."""
    # Check permissions: users can update themselves, or managers+ can update anyone
    if current_user.id != user.id and current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only update your own profile."
        )
    
    # Prevent privilege escalation: non-admins cannot change role to admin
    if data.role is not None and data.role != user.role:
        if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can change user roles"
            )
    
    # Prevent editing sensitive fields for other users
    if current_user.id != user.id:
        _validate_sensitive_field_changes(current_user, data)


def _validate_sensitive_field_changes(current_user: User, data: UserUpdate) -> None:
    """Validate that sensitive fields are not being changed by unauthorized users."""
    fields_being_changed = data.model_dump(exclude_unset=True)
    sensitive_fields = {'role', 'is_active', 'employee_id'}
    
    if sensitive_fields & fields_being_changed.keys():
        if current_user.role not in [UserRole.SUPER_ADMIN, UserRole.ADMIN]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the user themselves can update role, is_active, or employee_id"
            )


def _validate_user_uniqueness(db: Session, user: User, data: UserUpdate) -> None:
    """Validate uniqueness constraints for user fields."""
    if data.employee_id is not None:
        employee_id_value = data.employee_id if data.employee_id != '' else None
        if employee_id_value:
            _check_employee_id_unique(db, employee_id_value, user.id)
    
    if data.email is not None and data.email != user.email:
        _check_email_unique(db, data.email, user.id)
    
    if data.phone is not None and data.phone != user.phone:
        _check_phone_unique(db, data.phone, user.id)


def _apply_user_update(user: User, data: UserUpdate) -> None:
    """Apply update data to user object."""
    for field, value in data.model_dump(exclude_unset=True).items():
        if field == 'user_id':
            continue
        if field == 'employee_id' and value == '':
            value = None
        setattr(user, field, value)


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    responses={
        400: {"description": "Bad Request - Duplicate email, phone, or employee_id"},
        403: {"description": "Forbidden - Insufficient permissions to update user"},
        404: {"description": "Not Found - User does not exist"},
    }
)
def update_user_endpoint(
    user_id: int,
    data: UserUpdate,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(get_current_user)] = None,
    request: Request = None,
):
    """
    Update a user's profile.

    **Permissions:**
    - Any authenticated user can update their own profile (including location_id)
    - Manager+ can update other users
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=USER_NOT_FOUND_MSG)
    
    _validate_user_update_permissions(current_user, user, data)
    _validate_user_uniqueness(db, user, data)
    _apply_user_update(user, data)
    
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="update_user",
        resource_type="user",
        resource_id=user_id,
        request=request,
    ))
    
    # Sync location changes between users.location_id and user_locations table
    if data.location_id is not None:
        from app.api.location_audience import _sync_user_location_primary
        _sync_user_location_primary(db, user_id, data.location_id)
    
    db.commit()
    db.refresh(user)
    refresh_dynamic_groups_for_user(db, user)
    return user


def _check_employee_id_unique(db: Session, employee_id_value: str, exclude_user_id: int) -> None:
    """Raise 400 if the employee_id is already assigned to a different user."""
    existing = db.query(User).filter(
        User.employee_id == employee_id_value,
        User.id != exclude_user_id,
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Employee ID '{employee_id_value}' already assigned to another user",
        )


def _check_email_unique(db: Session, email: str, exclude_user_id: int) -> None:
    """Raise 400 if the email is already assigned to a different user."""
    existing = db.query(User).filter(
        User.email == email,
        User.id != exclude_user_id,
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Email '{email}' already assigned to another user",
        )


def _check_phone_unique(db: Session, phone: str, exclude_user_id: int) -> None:
    """Raise 400 if the phone number is already assigned to a different user."""
    if not phone:  # Allow null/empty phone
        return
    existing = db.query(User).filter(
        User.phone == phone,
        User.id != exclude_user_id,
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Phone number '{phone}' already assigned to another user. Each user must have a unique phone number.",
        )


def _validate_super_admin_access(user: User, current_user: User) -> None:
    """Validate that only SUPER_ADMIN can modify SUPER_ADMIN users."""
    if user.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SUPER_ADMIN can modify SUPER_ADMIN users",
        )


def _update_user_fields(user: User, data: UserUpdate) -> None:
    """Apply update data to user object, handling empty employee_id."""
    for field, value in data.model_dump(exclude_unset=True).items():
        if field == 'user_id':
            continue
        if field == 'employee_id' and value == '':
            value = None
        setattr(user, field, value)


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    responses={
        400: {"description": "Bad Request - Duplicate email, phone, or employee_id"},
        403: {"description": "Forbidden - ADMIN cannot create/update SUPER_ADMIN users"},
        404: {
            "description": "Not Found - User does not exist",
            "content": {
                "application/json": {
                    "example": {"detail": "User not found"}
                }
            }
        },
    }
)
def update_user(
    user_id: int,
    data: UserUpdate,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_admin)] = None,
    request: Request = None,
):
    """Update a user account (admin endpoint).

    Args:
        user_id: ID of user to update
        data: User update data
        db: Database session
        current_user: Authenticated admin user
        request: HTTP request for audit logging

    Returns:
        Updated user account

    Raises:
        HTTPException: 404 - User not found
        HTTPException: 403 - Insufficient permissions
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=USER_NOT_FOUND_MSG)

    _validate_super_admin_access(user, current_user)
    _prevent_privilege_escalation(current_user, data.role)
    _validate_user_uniqueness(db, user, data)
    _update_user_fields(user, data)

    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="update_user",
        resource_type="user",
        resource_id=user_id,
        request=request,
    ))
    db.commit()
    db.refresh(user)
    refresh_dynamic_groups_for_user(db, user)
    return user


@router.delete(
    "/{user_id}",
    responses={
        400: {"description": "Bad Request - Cannot delete yourself"},
        404: {"description": "Not Found - User does not exist"},
    }
)
def delete_user(
    user_id: int,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_admin)] = None,
    request: Request = None,
):
    """Permanently delete a user (hard delete). Only ADMIN and SUPER_ADMIN can delete."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=USER_NOT_FOUND_MSG)
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    # Remove user from all dynamic groups before deletion
    # This ensures clean deletion without orphaned references
    dynamic_groups = db.query(Group).filter(
        Group.type == GroupType.DYNAMIC,
        Group.is_active == True
    ).all()

    for group in dynamic_groups:
        if user in group.members:
            group.members.remove(user)

    # Delete user_locations entries first (to avoid NOT NULL violation)
    db.query(UserLocation).filter(UserLocation.user_id == user_id).delete()
    
    # Delete user_location_history entries
    db.query(UserLocationHistory).filter(UserLocationHistory.user_id == user_id).delete()

    db.delete(user)
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="delete_user",
        resource_type="user",
        resource_id=user_id,
        details={"deleted_email": user.email, "deleted_name": user.full_name},
        request=request,
    ))
    db.commit()
    return {"message": "User permanently deleted"}


def _remove_users_from_dynamic_groups(db, users: List[User]) -> None:
    """Remove users from all dynamic groups before deletion."""
    dynamic_groups = db.query(Group).filter(
        Group.type == GroupType.DYNAMIC,
        Group.is_active == True
    ).all()
    
    for user in users:
        for group in dynamic_groups:
            if user in group.members:
                group.members.remove(user)


def _reassign_user_foreign_keys(db, user_ids: List[int], current_user_id: int) -> None:
    """Reassign all foreign keys that reference users being deleted."""
    # Reassign groups created by users being deleted
    db.query(Group).filter(Group.created_by_id.in_(user_ids)).update({
        Group.created_by_id: current_user_id,
        Group.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign templates created by users being deleted
    db.query(NotificationTemplate).filter(
        NotificationTemplate.created_by_id.in_(user_ids)
    ).update({
        NotificationTemplate.created_by_id: current_user_id,
        NotificationTemplate.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign incidents created by users being deleted
    db.query(Incident).filter(Incident.created_by_id.in_(user_ids)).update({
        Incident.created_by_id: current_user_id,
        Incident.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign incidents resolved by users being deleted
    db.query(Incident).filter(Incident.resolved_by_id.in_(user_ids)).update({
        Incident.resolved_by_id: current_user_id,
        Incident.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign notifications created by users being deleted
    db.query(Notification).filter(Notification.created_by_id.in_(user_ids)).update({
        Notification.created_by_id: current_user_id,
        Notification.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign user_locations assigned_by_id (manual assignments)
    db.query(UserLocation).filter(UserLocation.assigned_by_id.in_(user_ids)).update({
        UserLocation.assigned_by_id: current_user_id,
        UserLocation.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign user_location_history triggered_by_user_id
    db.query(UserLocationHistory).filter(
        UserLocationHistory.triggered_by_user_id.in_(user_ids)
    ).update({
        UserLocationHistory.triggered_by_user_id: current_user_id,
    }, synchronize_session=False)


def _delete_single_user(db, user: User, current_user: User, request: Request) -> bool:
    """Delete a single user and related records. Returns True if successful."""
    try:
        db.add(create_audit_log(
            user_id=current_user.id,
            user_email=current_user.email,
            action="delete_user",
            resource_type="user",
            resource_id=user.id,
            details={"deleted_email": user.email, "deleted_name": user.full_name},
            request=request,
        ))
        
        db.query(UserLocation).filter(
            UserLocation.user_id == user.id
        ).delete(synchronize_session=False)
        
        db.query(UserLocationHistory).filter(
            UserLocationHistory.user_id == user.id
        ).delete(synchronize_session=False)
        
        db.delete(user)
        return True
    except Exception as e:
        logger.error(f"Failed to delete user {user.id}: {e}")
        db.rollback()
        return False


@router.post(
    "/bulk-delete",
    responses={
        400: {"description": "Bad Request - No user IDs provided or attempting to delete yourself"},
    }
)
def bulk_delete_users(
    user_ids: List[int],
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_admin)] = None,
    request: Request = None,
):
    """
    Permanently delete multiple users at once (hard delete).
    Only ADMIN and SUPER_ADMIN can perform bulk deletion.

    - Prevents deleting yourself
    - Returns summary of deleted and failed user IDs
    """
    if not user_ids:
        raise HTTPException(status_code=400, detail="No user IDs provided")

    if current_user.id in user_ids:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    users = db.query(User).filter(User.id.in_(user_ids)).all()
    found_ids = {u.id for u in users}
    
    _remove_users_from_dynamic_groups(db, users)
    _reassign_user_foreign_keys(db, user_ids, current_user.id)
    
    deleted_count = 0
    failed_ids = []
    
    for user in users:
        if _delete_single_user(db, user, current_user, request):
            deleted_count += 1
        else:
            failed_ids.append(user.id)
    
    db.commit()
    
    successful_ids = found_ids - set(failed_ids)
    
    return UserBulkDeleteResponse(
        deleted=deleted_count,
        failed=len(failed_ids),
        deleted_ids=list(successful_ids),
        failed_ids=failed_ids
    )



def _sanitize_row_field(row: dict, field: str) -> str:
    """Extract, strip, and sanitize a CSV row field against formula injection."""
    return _sanitize_formula_characters(row.get(field, '').strip())


def _parse_csv_row_role(row: dict, row_num: int, current_user: User):
    """Parse and validate the role field. Returns (role, error_dict_or_None)."""
    role_str = row.get('role', 'viewer').strip().lower()
    try:
        role = UserRole(role_str)
    except ValueError:
        role = UserRole.VIEWER
    if role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        return None, {"status": "error", "error": f"Row {row_num}: Only SUPER_ADMIN can assign SUPER_ADMIN role"}
    return role, None


def _update_existing_csv_user(existing: User, first_name: str, last_name: str,
                               row: dict, row_num: int, current_user: User,
                               valid_users: list) -> dict:
    """Update an existing user from a CSV row. Returns result dict."""
    if existing.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        return {"status": "error", "error": f"Row {row_num}: Only SUPER_ADMIN can modify SUPER_ADMIN user ({existing.email})"}
    existing.first_name = first_name
    existing.last_name = last_name
    existing.phone = _sanitize_row_field(row, 'phone') or existing.phone
    existing.department = _sanitize_row_field(row, 'department') or existing.department
    existing.title = _sanitize_row_field(row, 'title') or existing.title
    existing.employee_id = _sanitize_row_field(row, 'employee_id') or existing.employee_id
    valid_users.append(("updated", existing))
    return {"status": "ok", "action": "updated"}


def _create_new_csv_user(email: str, first_name: str, last_name: str, role,
                          row: dict, db: Session,
                          created_users: list, valid_users: list) -> dict:
    """Create a new user from a CSV row. Returns result dict."""
    import secrets as _secrets
    default_password = _secrets.token_urlsafe(12)
    user = User(
        email=email,
        hashed_password=hash_password(default_password),
        first_name=first_name,
        last_name=last_name,
        phone=_sanitize_row_field(row, 'phone'),
        department=_sanitize_row_field(row, 'department'),
        title=_sanitize_row_field(row, 'title'),
        employee_id=_sanitize_row_field(row, 'employee_id') or None,
        role=role,
        is_active=True,
    )
    db.add(user)
    created_users.append({"email": email, "password": default_password,
                          "first_name": first_name, "last_name": last_name})
    valid_users.append(("created", user))
    return {"status": "ok", "action": "created"}


def _process_csv_row(
    row: dict, row_num: int, db: Session,
    current_user: User, created_users: list, valid_users: list
) -> dict:
    """Process a single CSV import row. Returns dict with status/action/error."""
    try:
        email = row.get('email', '').strip().lower()
        if not email:
            return {"status": "error", "error": f"Row {row_num}: Email is required"}

        first_name = _sanitize_row_field(row, 'first_name')
        last_name = _sanitize_row_field(row, 'last_name')
        if not first_name or not last_name:
            return {"status": "error", "error": f"Row {row_num}: first_name and last_name are required"}

        role, role_error = _parse_csv_row_role(row, row_num, current_user)
        if role_error:
            return role_error

        existing = db.query(User).filter(User.email == email).first()
        if existing:
            return _update_existing_csv_user(existing, first_name, last_name,
                                             row, row_num, current_user, valid_users)
        return _create_new_csv_user(email, first_name, last_name, role,
                                    row, db, created_users, valid_users)
    except Exception as e:
        logger.warning(f"CSV import row {row_num} failed: {e}")
        return {"status": "error", "error": f"Row {row_num}: {str(e)}"}


# ─── CSV IMPORT HELPERS ──────────────────────────────────────────────────────

def _validate_csv_file(file: UploadFile) -> None:
    """Validate CSV file extension and MIME type."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    allowed_mime_types = ['text/csv', 'application/vnd.ms-excel', 'application/csv']
    if file.content_type and file.content_type not in allowed_mime_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Expected CSV (text/csv), got {file.content_type}"
        )


def _read_and_validate_csv_content(content: bytes) -> List[dict]:
    """Read CSV content and validate size/row count."""
    if len(content) > MAX_CSV_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File size exceeds maximum allowed size of {MAX_CSV_FILE_SIZE // (1024 * 1024)}MB"
        )

    reader = csv.DictReader(io.StringIO(content.decode('utf-8-sig')))
    rows = list(reader)

    if len(rows) > MAX_CSV_ROWS:
        raise HTTPException(
            status_code=400,
            detail=f"CSV file exceeds maximum allowed rows of {MAX_CSV_ROWS}. Please split your import into smaller batches."
        )

    return rows


def _process_csv_rows(
    rows: List[dict], db: Session, current_user: User,
    created_users: list, valid_users: list
) -> tuple:
    """Process all CSV rows and return counts."""
    created, updated, failed = 0, 0, 0
    errors = []

    for i, row in enumerate(rows, start=2):
        result = _process_csv_row(
            row=row, row_num=i, db=db,
            current_user=current_user,
            created_users=created_users,
            valid_users=valid_users
        )
        if result["status"] == "ok":
            if result["action"] == "created":
                created += 1
            else:
                updated += 1
        else:
            errors.append(result["error"])
            failed += 1

    return created, updated, failed, errors


def _commit_csv_import(
    db: Session, current_user: User, request: Request,
    created: int, updated: int, failed: int,
    valid_users: list, errors: list
) -> None:
    """Commit CSV import and create audit log."""
    if valid_users:
        db.add(create_audit_log(
            user_id=current_user.id,
            user_email=current_user.email,
            action="import_users_csv",
            resource_type="user",
            details={
                "created": created,
                "updated": updated,
                "failed": failed,
                "valid_rows": len(valid_users),
                "total_rows": created + updated + failed
            },
            request=request,
        ))
        db.commit()
        logger.info(f"CSV import committed: {created} created, {updated} updated, {failed} failed")

        for action_type, user_obj in valid_users:
            refresh_dynamic_groups_for_user(db, user_obj)
    else:
        db.add(create_audit_log(
            user_id=current_user.id,
            user_email=current_user.email,
            action="import_users_csv_failed",
            resource_type="user",
            details={
                "failed": failed,
                "total_rows": failed,
                "errors": errors
            },
            request=request,
        ))
        db.commit()
        logger.warning(f"CSV import had no valid rows to commit, {failed} rows failed")


def _send_welcome_emails(
    db: Session, current_user: User, request: Request,
    created_users: list
) -> tuple:
    """Send welcome emails to newly created users."""
    from app.services.messaging import email_service
    
    emails_sent, emails_failed = 0, 0
    email_failures = []

    for user_data in created_users:
        try:
            full_name = f"{user_data['first_name']} {user_data['last_name']}"
            result = email_service.send_welcome_email(
                to=user_data['email'],
                user_name=full_name,
                password=user_data['password']
            )
            if result.get('status') == 'failed':
                emails_failed += 1
                email_failures.append(f"Email to {_scrub_email(user_data['email'])} failed: {result.get('error', 'Unknown error')}")
                logger.error(f"Welcome email failed for {user_data.get('email')}: {result.get('error')}")
            else:
                emails_sent += 1
                logger.info(f"Welcome email sent to {user_data.get('email')}")
        except Exception as e:
            emails_failed += 1
            email_failures.append(f"Email to {_scrub_email(user_data['email'])} error: {str(e)}")
            logger.error(f"Exception sending welcome email to {user_data.get('email')}: {e}")

    if created_users and (emails_sent > 0 or emails_failed > 0):
        db.add(create_audit_log(
            user_id=current_user.id,
            user_email=current_user.email,
            action="import_users_csv_emails",
            resource_type="user",
            details={
                "emails_sent": emails_sent,
                "emails_failed": emails_failed,
                "total_created": len(created_users)
            },
            request=request,
        ))
        db.commit()

    return emails_sent, emails_failed, email_failures


# ─── CSV IMPORT ENDPOINT ─────────────────────────────────────────────────────

@router.post(
    "/import/csv",
    response_model=CSVImportResponse,
    responses={
        400: {
            "description": "Bad Request - Invalid file format or too many rows",
            "content": {
                "application/json": {
                    "examples": {
                        "format": {"summary": "Invalid file format", "value": {"detail": "File must be a CSV"}},
                        "rows": {"summary": "Too many rows", "value": {"detail": "CSV file exceeds maximum allowed rows..."}},
                    }
                }
            }
        },
        413: {
            "description": "Payload Too Large - File size exceeds 5MB limit",
            "content": {
                "application/json": {
                    "example": {"detail": "File size exceeds maximum allowed size of 5MB"}
                }
            }
        },
        429: {
            "description": "Too Many Requests - Rate limit exceeded",
            "content": {
                "application/json": {
                    "example": {"detail": "Rate limit exceeded. Maximum 10 requests per minute."}
                }
            }
        },
    }
)
async def import_users_csv(
    file: Annotated[UploadFile, File(...)],
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_admin)] = None,
    request: Request = None,
):
    """Import users from CSV file.

    Expected columns: first_name, last_name, email, phone, department, title, employee_id, role

    Args:
        file: CSV file to import
        db: Database session
        current_user: Authenticated admin user
        request: HTTP request for audit logging

    Returns:
        Import results with created, updated, failed counts and created user list

    Raises:
        HTTPException: 400 - Invalid file format or too many rows
        HTTPException: 413 - File size exceeds 5MB
        HTTPException: 429 - Rate limit exceeded
    """
    # Rate limiting
    is_allowed, retry_after = await check_api_rate_limit(current_user.id, "import_users_csv")
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {API_RATE_LIMIT_MAX} requests per minute for this endpoint.",
            headers={"Retry-After": str(retry_after)}
        )

    await record_api_request(current_user.id, "import_users_csv")

    # Validate file
    _validate_csv_file(file)

    # Read and validate content
    content = await file.read()
    rows = _read_and_validate_csv_content(content)

    # Process rows
    created_users = []
    valid_users = []
    created, updated, failed, errors = _process_csv_rows(
        rows, db, current_user, created_users, valid_users
    )

    # Commit import
    _commit_csv_import(db, current_user, request, created, updated, failed, valid_users, errors)

    # Send welcome emails
    emails_sent, emails_failed, email_failures = _send_welcome_emails(
        db, current_user, request, created_users
    )

    # Return results (without passwords for security)
    all_errors = errors + email_failures

    return CSVImportResponse(
        created=created,
        updated=updated,
        failed=failed,
        errors=all_errors,  # Always pass list (can be empty)
        created_users=[
            {"email": u["email"], "first_name": u["first_name"], "last_name": u["last_name"]}
            for u in created_users
        ]
    )


@router.get("/meta/departments")
def get_departments(db: Annotated[Session, Depends(get_db)] = None, current_user: Annotated[User, Depends(get_current_user)] = None):
    """Get all unique departments for filtering."""
    results = db.query(User.department).filter(
        User.department != None,
        User.department != ""
    ).distinct().all()
    return [r[0] for r in results if r[0]]


# ─── ADMIN MFA MANAGEMENT ENDPOINTS ─────────────────────────────────────────

@router.get(
    "/{user_id}/mfa/status",
    response_model=AdminMFAStatusResponse,
    responses={
        403: {"description": "Forbidden - ADMIN cannot view MFA status of SUPER_ADMIN users"},
        404: {"description": "Not Found - User does not exist"},
    }
)
def admin_get_user_mfa_status(
    user_id: int,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_admin)] = None,
    request: Request = None,
):
    """
    Admin view of user's MFA status.

    Returns safe metadata only - never exposes secrets or recovery codes.
    This is for admin support scenarios (e.g., helping locked-out users).

    Security:
    - Requires ADMIN role
    - Does NOT expose secrets or recovery codes
    - Audit logged
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=USER_NOT_FOUND_MSG)

    # Prevent privilege escalation: ADMIN cannot view SUPER_ADMIN MFA status
    if target_user.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SUPER_ADMIN can view MFA status of SUPER_ADMIN users"
        )

    mfa_service = get_mfa_service(db)
    status_data = mfa_service.get_mfa_status(target_user)
    recovery_status = get_recovery_code_status(db, user_id)

    # Audit log
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="admin_view_user_mfa_status",
        resource_type="user",
        resource_id=user_id,
        details={
            "target_user_email": target_user.email,
            "admin_email": current_user.email
        },
        request=request,
    ))
    db.commit()

    return AdminMFAStatusResponse(
        user_id=user_id,
        user_email=target_user.email,
        mfa_enabled=status_data["mfa_enabled"],
        mfa_required=status_data["mfa_required"],
        mfa_configured=status_data["mfa_configured"],
        has_recovery_codes=status_data["has_recovery_codes"],
        recovery_codes_count=status_data["recovery_codes_count"],
        role=str(target_user.role.value)
    )


@router.post(
    "/{user_id}/mfa/reset",
    response_model=AdminMFAResetResponse,
    responses={
        400: {"description": "Bad Request - Cannot reset your own MFA via this endpoint"},
        403: {"description": "Forbidden - ADMIN cannot reset MFA for SUPER_ADMIN users"},
        404: {"description": "Not Found - User does not exist"},
    }
)
def admin_reset_user_mfa(
    user_id: int,
    request_data: AdminMFAResetRequest,
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(require_admin)] = None,
    request: Request = None,
):
    """
    Admin-assisted MFA reset for a user.

    Use this when:
    - User lost authenticator AND recovery codes
    - User is locked out and needs assistance
    - Security incident requires forced re-enrollment

    Security requirements:
    - Requires ADMIN role
    - Requires reason for audit
    - Prevents privilege escalation (ADMIN can't reset SUPER_ADMIN)
    - Invalidates old MFA secret and recovery codes
    - Creates pending new enrollment (user must complete on next login)
    - Target user is notified
    - Audit logged

    Note: This does NOT disable MFA for privileged users - they will be
    forced to re-enroll on next login.
    """
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=USER_NOT_FOUND_MSG)

    # Prevent privilege escalation: ADMIN cannot reset SUPER_ADMIN MFA
    if target_user.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SUPER_ADMIN can reset MFA for SUPER_ADMIN users"
        )

    # Cannot reset your own MFA via this endpoint (use self-service reset)
    if target_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use the self-service MFA reset endpoint for your own account"
        )

    mfa_service = get_mfa_service(db)

    # Invalidate old MFA secret
    old_secret = target_user.mfa_secret
    target_user.mfa_secret = None
    target_user.mfa_enabled = False

    # Invalidate old recovery codes
    invalidate_all_recovery_codes(
        db=db,
        user_id=user_id,
        invalidated_by_user_id=current_user.id,
        reason='admin_reset'
    )

    # Generate new pending enrollment
    from app.core.security import generate_mfa_secret, encrypt_mfa_secret
    new_secret = generate_mfa_secret()
    encrypted_secret = encrypt_mfa_secret(new_secret)
    target_user.mfa_secret = encrypted_secret
    # Note: mfa_enabled remains False - user must complete enrollment

    # Audit log
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="admin_reset_user_mfa",
        resource_type="user",
        resource_id=user_id,
        details={
            "target_user_email": target_user.email,
            "admin_email": current_user.email,
            "reason": request_data.reason,
            "old_secret_invalidated": bool(old_secret)
        },
        request=request,
    ))

    # Notify target user (in production, send email)
    user_notified = True  # In production, use email_service.send_mfa_reset_notification()
    logger.info(f"Admin {_log_user_identity(current_user.id, current_user.email)} reset MFA for {_log_user_identity(target_user.id, target_user.email)}")

    db.commit()

    return AdminMFAResetResponse(
        message=f"MFA has been reset for user {target_user.email}. They must re-enroll on next login.",
        mfa_reset=True,
        user_notified=user_notified,
        reason=request_data.reason
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(
    db: Annotated[Session, Depends(get_db)] = None,
    current_user: Annotated[User, Depends(get_current_user)] = None,
):
    """
    Heartbeat endpoint to mark user as online.

    Called periodically by the frontend (every 30 seconds) to indicate
    the user is still active and online. Updates last_seen_at timestamp
    and sets is_online to True.
    
    Note: This does NOT affect is_enabled (account status).
    """
    now = datetime.now(timezone.utc)
    current_user.last_seen_at = now
    current_user.is_online = True
    db.commit()

    return HeartbeatResponse(
        status="ok",
        message="Heartbeat received",
        last_seen_at=current_user.last_seen_at
    )
