import io
import csv
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Optional
from app.database import get_db
from app.models import User, UserRole, AuditLog
from app.schemas import UserCreate, UserUpdate, UserResponse, UserListResponse, CSVImportResponse
from app.core.security import hash_password
from app.core.deps import get_current_user, require_admin, require_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users / People"])


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
    current_user: User = Depends(require_manager)
):
    query = db.query(User).filter(User.deleted_at == None)

    if search:
        query = query.filter(or_(
            User.first_name.ilike(f"%{search}%"),
            User.last_name.ilike(f"%{search}%"),
            User.email.ilike(f"%{search}%"),
            User.phone.ilike(f"%{search}%"),
            User.department.ilike(f"%{search}%"),
            User.employee_id.ilike(f"%{search}%"),
        ))
    if department:
        query = query.filter(User.department == department)
    if location_id:
        query = query.filter(User.location_id == location_id)
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    total = query.count()
    users = query.order_by(User.first_name).offset((page - 1) * page_size).limit(page_size).all()

    return UserListResponse(total=total, page=page, page_size=page_size, items=users)


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    if db.query(User).filter(User.email == data.email, User.deleted_at == None).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    if data.employee_id:
        if db.query(User).filter(User.employee_id == data.employee_id, User.deleted_at == None).first():
            raise HTTPException(status_code=400, detail="Employee ID already exists")

    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        first_name=data.first_name,
        last_name=data.last_name,
        phone=data.phone,
        whatsapp_number=data.whatsapp_number,
        department=data.department,
        title=data.title,
        employee_id=data.employee_id or None,
        role=data.role,
        location_id=data.location_id,
        preferred_channels=data.preferred_channels,
        is_active=True
    )
    db.add(user)
    db.add(AuditLog(
        user_id=current_user.id,
        action="create_user",
        resource_type="user",
        details={"email": data.email}
    ))
    try:
        db.commit()
        db.refresh(user)
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
    user = db.query(User).filter(User.id == user_id, User.deleted_at == None).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    # Check for user including soft-deleted
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Auto-restore soft-deleted user
    if user.deleted_at is not None:
        user.deleted_at = None
        user.is_active = True

    # Check for duplicate employee_id if it's being updated
    if data.employee_id is not None:
        employee_id_value = data.employee_id if data.employee_id != '' else None
        if employee_id_value:
            existing = db.query(User).filter(
                User.employee_id == employee_id_value,
                User.deleted_at == None,
                User.id != user_id  # Exclude current user from check
            ).first()
            if existing:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Employee ID '{employee_id_value}' already assigned to another user"
                )

    # Use exclude_unset=True to only update fields that were explicitly provided
    # This allows setting fields to None (to clear them) while not requiring all fields
    for field, value in data.model_dump(exclude_unset=True).items():
        if field == 'employee_id' and value == '':
            value = None
        setattr(user, field, value)

    db.add(AuditLog(user_id=current_user.id, action="update_user", resource_type="user", resource_id=user_id))
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id, User.deleted_at == None).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    from datetime import datetime, timezone
    user.deleted_at = datetime.now(timezone.utc)
    user.is_active = False
    db.add(AuditLog(user_id=current_user.id, action="delete_user", resource_type="user", resource_id=user_id))
    db.commit()
    return {"message": "User deleted successfully"}


@router.post("/import/csv", response_model=CSVImportResponse)
async def import_users_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Import users from CSV. Expected columns:
    first_name, last_name, email, phone, department, title, employee_id, role

    Sends welcome emails with login credentials to newly created users.
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    content = await file.read()
    reader = csv.DictReader(io.StringIO(content.decode('utf-8-sig')))

    created, updated, failed = 0, 0, 0
    errors = []
    created_users = []  # Track new users for email sending
    email_failures = []

    for i, row in enumerate(reader, start=2):
        try:
            email = row.get('email', '').strip().lower()
            if not email:
                errors.append(f"Row {i}: Email is required")
                failed += 1
                continue

            first_name = row.get('first_name', '').strip()
            last_name = row.get('last_name', '').strip()
            if not first_name or not last_name:
                errors.append(f"Row {i}: first_name and last_name are required")
                failed += 1
                continue

            # Check for existing user (including soft-deleted)
            existing = db.query(User).filter(User.email == email).first()
            is_restored = False

            role_str = row.get('role', 'viewer').strip().lower()
            try:
                role = UserRole(role_str)
            except ValueError:
                role = UserRole.VIEWER

            if existing:
                # Restore soft-deleted user
                if existing.deleted_at is not None:
                    existing.deleted_at = None
                    existing.is_active = True
                    is_restored = True

                # Update user fields
                existing.first_name = first_name
                existing.last_name = last_name
                existing.phone = row.get('phone', '').strip() or existing.phone
                existing.department = row.get('department', '').strip() or existing.department
                existing.title = row.get('title', '').strip() or existing.title
                existing.employee_id = row.get('employee_id', '').strip() or existing.employee_id
                updated += 1
                if is_restored:
                    logger.info(f"Restored soft-deleted user: {email}")
            else:
                import secrets
                default_password = secrets.token_urlsafe(12)
                user = User(
                    email=email,
                    hashed_password=hash_password(default_password),
                    first_name=first_name,
                    last_name=last_name,
                    phone=row.get('phone', '').strip(),
                    department=row.get('department', '').strip(),
                    title=row.get('title', '').strip(),
                    employee_id=row.get('employee_id', '').strip() or None,
                    role=role,
                    is_active=True
                )
                db.add(user)
                created += 1
                # Track new user credentials for email sending
                created_users.append({
                    "email": email,
                    "password": default_password,
                    "first_name": first_name,
                    "last_name": last_name
                })

        except Exception as e:
            errors.append(f"Row {i}: {str(e)}")
            failed += 1

    # Commit all users to database first
    db.add(AuditLog(
        user_id=current_user.id,
        action="import_users_csv",
        resource_type="user",
        details={"created": created, "updated": updated, "failed": failed}
    ))
    db.commit()

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
                email_failures.append(f"Email to {user_data['email']} failed: {result.get('error', 'Unknown error')}")
                logger.error(f"Welcome email failed for {user_data['email']}: {result.get('error')}")
            else:
                logger.info(f"Welcome email sent to {user_data['email']}")
        except Exception as e:
            email_failures.append(f"Email to {user_data['email']} error: {str(e)}")
            logger.error(f"Exception sending welcome email to {user_data['email']}: {e}")

    # Add errors to response if any
    all_errors = errors + email_failures

    return CSVImportResponse(
        created=created,
        updated=updated,
        failed=failed,
        errors=all_errors[:20],  # Return first 20 errors
        created_users=created_users
    )


@router.get("/meta/departments")
def get_departments(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get all unique departments for filtering."""
    results = db.query(User.department).filter(
        User.department != None,
        User.department != "",
        User.deleted_at == None
    ).distinct().all()
    return [r[0] for r in results if r[0]]
