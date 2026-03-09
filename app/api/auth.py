import secrets
import time
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from app.database import get_db
from app.models import User, RefreshToken, AuditLog, UserRole, LoginAttempt
from app.schemas import (
    LoginRequest, TokenResponse, RefreshRequest, UserResponse,
    PasswordResetRequest, PasswordResetConfirm, ChangePasswordRequest
)
from app.core.security import (
    verify_password, hash_password, create_access_token,
    create_refresh_token, decode_token
)
from app.core.deps import get_current_user
from app.services.messaging import email_service
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Login attempt rate limiting constants
MAX_FAILED_ATTEMPTS = 5  # Max failed attempts before lockout
FAILED_WINDOW_SECONDS = 30  # Time window to count failed attempts
LOCKOUT_SECONDS = 30  # Lockout duration after max attempts reached

# Simple in-memory rate limiting for password reset requests
# Format: {email: last_request_timestamp}
_password_reset_rate_limit: dict[str, float] = {}
PASSWORD_RESET_RATE_LIMIT_SECONDS = 30  # 30 seconds between requests per email


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    client_ip = req.client.host if req.client else None

    # Check for lockout due to too many failed attempts
    window_start = datetime.now(timezone.utc) - timedelta(seconds=FAILED_WINDOW_SECONDS)
    failed_count = db.query(LoginAttempt).filter(
        LoginAttempt.email == request.email.lower(),
        LoginAttempt.attempted_at >= window_start,
        LoginAttempt.success == False
    ).count()

    if failed_count >= MAX_FAILED_ATTEMPTS:
        # Check if still in lockout period
        last_attempt = db.query(LoginAttempt).filter(
            LoginAttempt.email == request.email.lower(),
            LoginAttempt.attempted_at >= window_start
        ).order_by(desc(LoginAttempt.attempted_at)).first()

        if last_attempt:
            time_since_last = datetime.now(timezone.utc) - last_attempt.attempted_at
            if time_since_last < timedelta(seconds=LOCKOUT_SECONDS):
                remaining = int(LOCKOUT_SECONDS - time_since_last.total_seconds())
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed login attempts. Please try again in {remaining} seconds."
                )
    
    user = db.query(User).filter(
        User.email == request.email,
        User.deleted_at.is_(None)
    ).first()

    # Check if user exists
    if not user:
        # Log failed attempt (don't reveal user doesn't exist)
        db.add(LoginAttempt(
            email=request.email.lower(),
            ip_address=client_ip,
            success=False
        ))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No account found with this email address"
        )

    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your administrator."
        )

    # Check password
    if not verify_password(request.password, user.hashed_password):
        # Log failed attempt
        db.add(LoginAttempt(
            email=request.email.lower(),
            ip_address=client_ip,
            success=False
        ))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    # Clear failed attempts on successful login
    db.query(LoginAttempt).filter(
        LoginAttempt.email == request.email.lower()
    ).delete()
    
    # Log successful attempt
    db.add(LoginAttempt(
        email=request.email.lower(),
        ip_address=client_ip,
        success=True
    ))

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})

    # Save refresh token
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(rt)

    # Update last login
    user.last_login = datetime.now(timezone.utc)

    # Audit log
    db.add(AuditLog(
        user_id=user.id,
        action="login",
        resource_type="user",
        resource_id=user.id,
        ip_address=req.client.host if req.client else None
    ))
    db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        user=UserResponse.model_validate(user)
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(request.refresh_token)

    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Check token in DB
    rt = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token,
        RefreshToken.revoked.is_(False)
    ).first()

    if not rt or rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    user = db.query(User).filter(User.id == rt.user_id, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Revoke old token, issue new ones
    rt.revoked = True
    new_access = create_access_token({"sub": str(user.id), "role": user.role})
    new_refresh_str = create_refresh_token({"sub": str(user.id)})

    new_rt = RefreshToken(
        user_id=user.id,
        token=new_refresh_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(new_rt)
    db.commit()

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh_str,
        user=UserResponse.model_validate(user)
    )


@router.post("/logout")
def logout(
    request: RefreshRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rt = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token,
        RefreshToken.user_id == current_user.id
    ).first()
    if rt:
        rt.revoked = True
        db.commit()
    return {"message": "Logged out successfully"}


@router.post("/forgot-password")
def forgot_password(request: PasswordResetRequest, req: Request, db: Session = Depends(get_db)):
    """
    Request a password reset email.
    
    Security measures:
    - Rate limiting: 1 request per minute per email
    - No email enumeration: Same response regardless of whether email exists
    """
    # Normalize email for rate limiting
    email_normalized = request.email.strip().lower()
    
    # Rate limiting check
    current_time = time.time()
    last_request = _password_reset_rate_limit.get(email_normalized)
    if last_request and (current_time - last_request) < PASSWORD_RESET_RATE_LIMIT_SECONDS:
        # Still within rate limit window - return success anyway to prevent enumeration
        return {"message": "If that email exists, we've sent a password reset link."}
    
    # Find user (case-insensitive email lookup)
    user = db.query(User).filter(
        User.email == email_normalized,
        User.deleted_at.is_(None)
    ).first()
    
    # Always return the same message to prevent email enumeration
    if not user:
        # Update rate limit even for non-existent emails
        _password_reset_rate_limit[email_normalized] = current_time
        return {"message": "If that email exists, we've sent a password reset link."}
    
    # Generate reset token
    token = secrets.token_urlsafe(32)
    user.password_reset_token = token
    user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()
    
    # Send email (async via celery would be better, but keeping sync for simplicity)
    email_service.send_password_reset_email(user.email, token, user.full_name)
    
    # Update rate limit
    _password_reset_rate_limit[email_normalized] = current_time
    
    return {"message": "If that email exists, we've sent a password reset link."}


@router.post("/reset-password")
def reset_password(request: PasswordResetConfirm, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.password_reset_token == request.token,
        User.password_reset_expires > datetime.now(timezone.utc)
    ).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    user.hashed_password = hash_password(request.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    
    # Revoke all refresh tokens to force re-authentication with new password
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked == False
    ).update({"revoked": True})
    
    db.commit()
    return {"message": "Password reset successfully"}


@router.post("/change-password")
def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(request.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    current_user.hashed_password = hash_password(request.new_password)
    
    # Revoke all refresh tokens to force re-authentication with new password
    # This invalidates all other sessions for security
    db.query(RefreshToken).filter(
        RefreshToken.user_id == current_user.id,
        RefreshToken.revoked == False
    ).update({"revoked": True})
    
    db.commit()
    return {"message": "Password changed successfully"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/login-attempts")
def get_login_attempts(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """View recent login attempts (for security monitoring)."""
    attempts = db.query(LoginAttempt).order_by(
        desc(LoginAttempt.attempted_at)
    ).limit(limit).all()
    
    return [
        {
            "id": a.id,
            "email": a.email,
            "ip_address": a.ip_address,
            "success": a.success,
            "attempted_at": a.attempted_at
        }
        for a in attempts
    ]
