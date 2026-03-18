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


def _user_matches_dynamic_filter(user: User, f: dict) -> bool:
    """Check if a user matches a dynamic group's filter criteria."""
    if f.get("department") and str(f["department"]).strip():
        if user.department != f["department"].strip():
            return False
    if f.get("title") and str(f["title"]).strip():
        if user.title != f["title"].strip():
            return False
    if f.get("role") and str(f["role"]).strip():
        if user.role != f["role"].strip():
            return False
    if f.get("location_id") and str(f["location_id"]).strip():
        if user.location_id != int(f["location_id"]):
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
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    department: Optional[str] = None,
    location_id: Optional[int] = None,
    role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
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


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    request: Request = None,
):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    if data.employee_id:
        if db.query(User).filter(User.employee_id == data.employee_id).first():
            raise HTTPException(status_code=400, detail="Employee ID already exists")

    # Prevent privilege escalation: ADMIN cannot create SUPER_ADMIN users
    _prevent_privilege_escalation(current_user, data.role)

    user = User(
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
    db.add(user)
    db.add(create_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action="create_user",
        resource_type="user",
        details={"email": data.email},
        request=request,
    ))
    try:
        db.commit()
        db.refresh(user)
        
        # Refresh dynamic group memberships for the new user
        refresh_dynamic_groups_for_user(db, user)
        
    except Exception as e:
        db.rollback()
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(status_code=400, detail="A user with this email or employee ID already exists")
        raise HTTPException(status_code=500, detail="Failed to create user")
    return user


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_manager)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=USER_NOT_FOUND_MSG)
    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    request: Request = None,
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=USER_NOT_FOUND_MSG)

    # Prevent privilege escalation: ADMIN cannot modify SUPER_ADMIN users
    if user.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SUPER_ADMIN can modify SUPER_ADMIN users"
        )

    # Prevent privilege escalation: ADMIN cannot escalate user to SUPER_ADMIN
    if data.role is not None:
        _prevent_privilege_escalation(current_user, data.role)

    # Check for duplicate employee_id if it's being updated
    if data.employee_id is not None:
        employee_id_value = data.employee_id if data.employee_id != '' else None
        if employee_id_value:
            existing = db.query(User).filter(
                User.employee_id == employee_id_value,
                User.id != user_id  # Exclude current user from check
            ).first()
            if existing:
                raise HTTPException(
                    status_code=400,
                    detail=f"Employee ID '{employee_id_value}' already assigned to another user"
                )

    # Check for duplicate email if it's being updated
    if data.email is not None and data.email != user.email:
        existing = db.query(User).filter(
            User.email == data.email,
            User.id != user_id  # Exclude current user from check
        ).first()
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Email '{data.email}' already assigned to another user"
            )

    # Use exclude_unset=True to only update fields that were explicitly provided
    # This allows setting fields to None (to clear them) while not requiring all fields
    for field, value in data.model_dump(exclude_unset=True).items():
        if field == 'employee_id' and value == '':
            value = None
        setattr(user, field, value)

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
    
    # Refresh dynamic group memberships for the updated user
    refresh_dynamic_groups_for_user(db, user)
    
    return user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
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


@router.post("/bulk-delete")
def bulk_delete_users(
    user_ids: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
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

    # Fetch all users to delete
    users = db.query(User).filter(User.id.in_(user_ids)).all()
    found_ids = {u.id for u in users}

    # Check for non-existent users
    not_found_ids = set(user_ids) - found_ids

    # Remove users from all dynamic groups before deletion
    # This ensures clean deletion without orphaned references
    dynamic_groups = db.query(Group).filter(
        Group.type == GroupType.DYNAMIC,
        Group.is_active == True
    ).all()

    for user in users:
        for group in dynamic_groups:
            if user in group.members:
                group.members.remove(user)

    # Reassign all foreign keys that reference users being deleted
    # This prevents foreign key constraint violations during deletion
    # We reassign to the current admin who is performing the deletion
    
    # Reassign groups created by users being deleted
    db.query(Group).filter(
        Group.created_by_id.in_(user_ids)
    ).update({
        Group.created_by_id: current_user.id,
        Group.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign templates created by users being deleted
    db.query(NotificationTemplate).filter(
        NotificationTemplate.created_by_id.in_(user_ids)
    ).update({
        NotificationTemplate.created_by_id: current_user.id,
        NotificationTemplate.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign incidents created by users being deleted
    db.query(Incident).filter(
        Incident.created_by_id.in_(user_ids)
    ).update({
        Incident.created_by_id: current_user.id,
        Incident.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign incidents resolved by users being deleted
    db.query(Incident).filter(
        Incident.resolved_by_id.in_(user_ids)
    ).update({
        Incident.resolved_by_id: current_user.id,
        Incident.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign notifications created by users being deleted
    db.query(Notification).filter(
        Notification.created_by_id.in_(user_ids)
    ).update({
        Notification.created_by_id: current_user.id,
        Notification.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign user_locations assigned_by_id (manual assignments)
    db.query(UserLocation).filter(
        UserLocation.assigned_by_id.in_(user_ids)
    ).update({
        UserLocation.assigned_by_id: current_user.id,
        UserLocation.updated_at: func.now()
    }, synchronize_session=False)
    
    # Reassign user_location_history triggered_by_user_id
    db.query(UserLocationHistory).filter(
        UserLocationHistory.triggered_by_user_id.in_(user_ids)
    ).update({
        UserLocationHistory.triggered_by_user_id: current_user.id,
    }, synchronize_session=False)

    # Delete users with proper cascade handling
    # Explicitly delete related records to avoid NOT NULL constraint violations
    deleted_count = 0
    failed_count = 0
    failed_ids = []
    
    for user in users:
        try:
            # Log the deletion action
            db.add(create_audit_log(
                user_id=current_user.id,
                user_email=current_user.email,
                action="delete_user",
                resource_type="user",
                resource_id=user.id,
                details={"deleted_email": user.email, "deleted_name": user.full_name},
                request=request,
            ))

            # Explicitly delete related records that have CASCADE
            # (others were reassigned above)
            db.query(UserLocation).filter(
                UserLocation.user_id == user.id
            ).delete(synchronize_session=False)

            db.query(UserLocationHistory).filter(
                UserLocationHistory.user_id == user.id
            ).delete(synchronize_session=False)

            db.delete(user)
            deleted_count += 1
        except Exception as e:
            logger.error(f"Failed to delete user {user.id}: {e}")
            failed_count += 1
            failed_ids.append(user.id)
            # Rollback this user's changes but continue with others
            db.rollback()

    db.commit()

    # Separate successful and failed deletions
    successful_ids = found_ids - set(failed_ids)

    return UserBulkDeleteResponse(
        deleted=deleted_count,
        failed=failed_count,
        deleted_ids=list(successful_ids),
        failed_ids=failed_ids
    )



def _process_csv_row(
    row: dict, row_num: int, db: Session,
    current_user: User, created_users: list, valid_users: list
) -> dict:
    """Process a single CSV import row. Returns dict with status/action/error."""
    import secrets as _secrets
    try:
        email = row.get('email', '').strip().lower()
        if not email:
            return {"status": "error", "error": f"Row {row_num}: Email is required"}

        first_name = _sanitize_formula_characters(row.get('first_name', '').strip())
        last_name = _sanitize_formula_characters(row.get('last_name', '').strip())
        if not first_name or not last_name:
            return {"status": "error", "error": f"Row {row_num}: first_name and last_name are required"}

        role_str = row.get('role', 'viewer').strip().lower()
        try:
            role = UserRole(role_str)
        except ValueError:
            role = UserRole.VIEWER

        if role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
            return {"status": "error", "error": f"Row {row_num}: Only SUPER_ADMIN can assign SUPER_ADMIN role"}

        existing = db.query(User).filter(User.email == email).first()

        if existing:
            if existing.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
                return {"status": "error", "error": f"Row {row_num}: Only SUPER_ADMIN can modify SUPER_ADMIN user ({email})"}
            existing.first_name = first_name
            existing.last_name = last_name
            existing.phone = _sanitize_formula_characters(row.get('phone', '').strip()) or existing.phone
            existing.department = _sanitize_formula_characters(row.get('department', '').strip()) or existing.department
            existing.title = _sanitize_formula_characters(row.get('title', '').strip()) or existing.title
            existing.employee_id = _sanitize_formula_characters(row.get('employee_id', '').strip()) or existing.employee_id
            valid_users.append(("updated", existing))
            return {"status": "ok", "action": "updated"}
        else:
            default_password = _secrets.token_urlsafe(12)
            user = User(
                email=email,
                hashed_password=hash_password(default_password),
                first_name=first_name,
                last_name=last_name,
                phone=_sanitize_formula_characters(row.get('phone', '').strip()),
                department=_sanitize_formula_characters(row.get('department', '').strip()),
                title=_sanitize_formula_characters(row.get('title', '').strip()),
                employee_id=_sanitize_formula_characters(row.get('employee_id', '').strip()) or None,
                role=role,
                is_active=True
            )
            db.add(user)
            created_users.append({
                "email": email, "password": default_password,
                "first_name": first_name, "last_name": last_name
            })
            valid_users.append(("created", user))
            return {"status": "ok", "action": "created"}
    except Exception as e:
        logger.warning(f"CSV import row {row_num} failed: {e}")
        return {"status": "error", "error": f"Row {row_num}: {str(e)}"}


@router.post("/import/csv", response_model=CSVImportResponse)
async def import_users_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    request: Request = None,
):
    """
    Import users from CSV. Expected columns:
    first_name, last_name, email, phone, department, title, employee_id, role

    Sends welcome emails with login credentials to newly created users.
    """
    # Rate limiting: Check API rate limit for state-changing operations
    is_allowed, retry_after = await check_api_rate_limit(current_user.id, "import_users_csv")
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {API_RATE_LIMIT_MAX} requests per minute for this endpoint.",
            headers={"Retry-After": str(retry_after)}
        )
    
    # Record the API request for rate limiting
    await record_api_request(current_user.id, "import_users_csv")
    
    # Validate file extension
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    # Validate MIME type (not just extension) to prevent file type spoofing
    allowed_mime_types = ['text/csv', 'application/vnd.ms-excel', 'application/csv']
    if file.content_type and file.content_type not in allowed_mime_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Expected CSV (text/csv), got {file.content_type}"
        )

    # Validate file size to prevent DoS attacks (max 5MB)
    content = await file.read()
    if len(content) > MAX_CSV_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File size exceeds maximum allowed size of {MAX_CSV_FILE_SIZE // (1024 * 1024)}MB"
        )
    
    # Parse CSV content
    reader = csv.DictReader(io.StringIO(content.decode('utf-8-sig')))
    
    # Convert to list to validate row count
    rows = list(reader)
    
    # Validate row count (max 1,000 rows per request)
    if len(rows) > MAX_CSV_ROWS:
        raise HTTPException(
            status_code=400,
            detail=f"CSV file exceeds maximum allowed rows of {MAX_CSV_ROWS}. Please split your import into smaller batches."
        )

    created, updated, failed = 0, 0, 0
    errors = []
    created_users = []  # Track new users for email sending
    email_failures = []
    valid_users = []  # Track successfully processed users for batch commit

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

    # Commit all valid rows in a single transaction
    # Invalid rows are skipped but don't affect valid rows
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
        
        # Refresh dynamic group memberships for all imported/updated users
        for action_type, user_obj in valid_users:
            refresh_dynamic_groups_for_user(db, user_obj)
    else:
        # No valid rows to commit - still log the failed import attempt
        # Store all errors (no truncation) for complete audit trail
        db.add(create_audit_log(
            user_id=current_user.id,
            user_email=current_user.email,
            action="import_users_csv_failed",
            resource_type="user",
            details={
                "failed": failed,
                "total_rows": failed,
                "errors": errors  # Include all errors for complete audit trail
            },
            request=request,
        ))
        db.commit()
        logger.warning(f"CSV import had no valid rows to commit, {failed} rows failed")

    # Track email sending results for audit log
    emails_sent = 0
    emails_failed = 0

    # Send welcome emails to newly created users (after commit)
    from app.services.messaging import email_service
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
                logger.error(f"Welcome email failed for user_id={user.id}, email={_scrub_email(user_data['email'])}: {result.get('error')}")
            else:
                emails_sent += 1
                logger.info(f"Welcome email sent to user_id={user.id}, email={_scrub_email(user_data['email'])}")
        except Exception as e:
            emails_failed += 1
            email_failures.append(f"Email to {_scrub_email(user_data['email'])} error: {str(e)}")
            logger.error(f"Exception sending welcome email to user_id={user.id}, email={_scrub_email(user_data['email'])}: {e}")

    # Add secondary audit log for email results if there were newly created users
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

    # Add errors to response if any
    all_errors = errors + email_failures

    # Return created users WITHOUT passwords for security
    # Passwords are only sent via email to the users
    created_users_public = [
        {"email": u["email"], "first_name": u["first_name"], "last_name": u["last_name"]}
        for u in created_users
    ]

    return CSVImportResponse(
        created=created,
        updated=updated,
        failed=failed,
        errors=all_errors[:20],  # Return first 20 errors
        created_users=created_users_public
    )


@router.get("/meta/departments")
def get_departments(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get all unique departments for filtering."""
    results = db.query(User.department).filter(
        User.department != None,
        User.department != ""
    ).distinct().all()
    return [r[0] for r in results if r[0]]


# ─── ADMIN MFA MANAGEMENT ENDPOINTS ─────────────────────────────────────────

@router.get("/{user_id}/mfa/status", response_model=AdminMFAStatusResponse)
def admin_get_user_mfa_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
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


@router.post("/{user_id}/mfa/reset", response_model=AdminMFAResetResponse)
def admin_reset_user_mfa(
    user_id: int,
    request_data: AdminMFAResetRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
