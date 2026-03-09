import secrets
import time
import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
import redis
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
from app.core.deps import get_current_user, require_admin
from app.services.messaging import email_service
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Simple in-memory rate limiting for password reset requests
# Format: {email: last_request_timestamp}
_password_reset_rate_limit: dict[str, float] = {}
PASSWORD_RESET_RATE_LIMIT_SECONDS = 30  # 30 seconds between requests per email

# Redis-based login rate limiting constants
ACCOUNT_LOCKOUT_THRESHOLD = 5  # Failed attempts before account lockout
IP_RATE_LIMIT_MAX_ATTEMPTS = 20  # Max attempts per IP across all accounts
IP_RATE_LIMIT_WINDOW_SECONDS = 600  # 10 minutes


def _get_redis_client() -> redis.Redis:
    """
    Get a synchronous Redis client for login rate limiting.
    Uses sync client because login is a sync function.
    Fails closed (raises exception) if Redis is unavailable.
    """
    return redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
    )


def _get_client_ip(request: Request) -> str:
    """
    Extract client IP address from request.
    
    Uses request.client.host exclusively (trusted source from ASGI).
    X-Forwarded-For is NOT used here because it is user-controlled and
    can be spoofed by attackers. Using it would allow bypassing IP-based
    rate limiting by simply sending a fake header.
    
    Raises HTTPException 400 if client IP cannot be determined.
    """
    if not request.client or not request.client.host:
        # Fail closed - cannot determine IP, deny the request
        # This prevents attacks where client info is missing/malformed
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to determine client IP"
        )
    return request.client.host


def check_ip_rate_limit(ip_address: str) -> tuple[bool, int]:
    """
    Check if IP address has exceeded rate limit (read-only, does NOT increment).
    
    The actual counting happens in record_ip_attempt() which is called on
    every login attempt (both success and failure paths in login()).
    This separation ensures the check itself doesn't inflate the count.
    
    Returns:
        tuple: (is_allowed, retry_after_seconds)
    
    Redis key: lockout:ip:{ip_address}
    Stores count of attempts in the current window.
    """
    r = _get_redis_client()
    key = f"lockout:ip:{ip_address}"
    
    current_count = r.get(key)
    if current_count is None:
        return True, 0
    
    count = int(current_count)
    if count >= IP_RATE_LIMIT_MAX_ATTEMPTS:
        # Rate limit exceeded, get TTL for retry-after header
        ttl = r.ttl(key)
        return False, ttl if ttl > 0 else IP_RATE_LIMIT_WINDOW_SECONDS
    
    return True, 0


def record_ip_attempt(ip_address: str) -> None:
    """
    Atomically record a login attempt for IP rate limiting.
    
    Called on EVERY login attempt (success or failure) to accurately track
    request volume per IP. Uses atomic INCR to prevent race conditions.
    If the key expired between check and record, re-creates it with fresh TTL.
    """
    r = _get_redis_client()
    key = f"lockout:ip:{ip_address}"
    
    # Atomic increment; INCR creates key with value 1 if missing
    current_count = r.incr(key)
    if current_count == 1:
        # Key was new or expired, set fresh TTL window
        r.expire(key, IP_RATE_LIMIT_WINDOW_SECONDS)


def check_account_lockout(user_id: int) -> tuple[bool, int]:
    """
    Check if account is currently locked out.

    Returns:
        tuple: (is_allowed, retry_after_seconds)

    Redis key: lockout:account:{user_id}
    Stores: attempt_count and lockout_until timestamp (pipe-separated)
    
    Parsing is safe: malformed data is logged, deleted, and treated as 0 attempts.
    """
    r = _get_redis_client()
    key = f"lockout:account:{user_id}"

    data = r.get(key)
    if data is None:
        return True, 0

    # Safe parsing: handle malformed data gracefully
    try:
        parts = data.split("|")
        if len(parts) != 2:
            logger.warning(f"Malformed lockout data for user {user_id}: wrong format, deleting key")
            r.delete(key)
            return True, 0
        attempt_count = int(parts[0])
        lockout_until = int(parts[1])
    except (ValueError, IndexError) as e:
        # Malformed data - log, delete corrupted key, fail open for this parse error only
        logger.warning(f"Malformed lockout data for user {user_id}: {e}, deleting key")
        r.delete(key)
        return True, 0

    if lockout_until > 0:
        now = int(time.time())
        if now < lockout_until:
            return False, lockout_until - now
        # Lockout expired — preserve attempt count so tier escalation works.
        # Clear only the lockout timestamp, keep the attempt count intact.
        # Without this, an attacker resets to 5 free attempts after every expiry.
        r.set(key, f"{attempt_count}|0")
        # Set a generous TTL so stale keys eventually self-clean (24h)
        r.expire(key, 86400)

    return True, 0


def record_failed_login(user_id: int) -> int:
    """
    Record a failed login attempt and apply lockout if threshold reached.

    Exponential backoff tiers:
    - 1st lockout (5 fails)  → 1 minute
    - 2nd lockout (10 fails) → 5 minutes
    - 3rd lockout (15 fails) → 15 minutes
    - 4th+ lockout (20+ fails) → 1 hour

    Returns the retry_after seconds if locked out, 0 otherwise.
    
    Parsing is safe: malformed data is logged, deleted, and treated as 0 attempts.
    """
    r = _get_redis_client()
    key = f"lockout:account:{user_id}"

    data = r.get(key)
    if data is None:
        attempt_count = 0
    else:
        # Safe parsing: handle malformed data gracefully
        try:
            parts = data.split("|")
            if len(parts) != 2:
                logger.warning(f"Malformed lockout data for user {user_id}: wrong format, resetting counter")
                r.delete(key)
                attempt_count = 0
            else:
                attempt_count = int(parts[0])
        except (ValueError, IndexError) as e:
            # Malformed data - log, delete corrupted key, reset counter
            logger.warning(f"Malformed lockout data for user {user_id}: {e}, resetting counter")
            r.delete(key)
            attempt_count = 0

    attempt_count += 1
    
    # Determine lockout duration based on attempt count tier
    lockout_seconds = 0
    if attempt_count >= ACCOUNT_LOCKOUT_THRESHOLD:
        if attempt_count < 10:
            # 1st lockout tier: 5-9 fails → 1 minute
            lockout_seconds = 60
        elif attempt_count < 15:
            # 2nd lockout tier: 10-14 fails → 5 minutes
            lockout_seconds = 300
        elif attempt_count < 20:
            # 3rd lockout tier: 15-19 fails → 15 minutes
            lockout_seconds = 900
        else:
            # 4th+ lockout tier: 20+ fails → 1 hour
            lockout_seconds = 3600
    
    lockout_until = int(time.time()) + lockout_seconds if lockout_seconds > 0 else 0
    r.setex(key, max(lockout_seconds, 86400), f"{attempt_count}|{lockout_until}")
    
    return lockout_seconds if lockout_seconds > 0 else 0


def reset_account_lockout(user_id: int) -> None:
    """
    Reset account lockout counter on successful login.
    """
    r = _get_redis_client()
    key = f"lockout:account:{user_id}"
    r.delete(key)


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    client_ip = _get_client_ip(req)
    
    # Normalize email to prevent case-based lockout bypass
    # e.g., "Admin@Site.com" vs "admin@site.com" must hit the same lockout counter
    normalized_email = request.email.strip().lower()
    
    # STEP 1: Check IP-based rate limit FIRST (before any user lookup)
    # This prevents enumeration attacks and applies across ALL accounts
    ip_allowed, ip_retry_after = check_ip_rate_limit(client_ip)
    if not ip_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Invalid credentials",
            headers={"Retry-After": str(ip_retry_after)}
        )

    # STEP 2: Look up user by email (case-insensitive)
    # Use func.lower for case-insensitive comparison to match normalized_email
    user = db.query(User).filter(
        func.lower(User.email) == normalized_email,
        User.deleted_at.is_(None)
    ).first()
    
    # STEP 3: If user exists, check account lockout
    # If user doesn't exist, skip account lockout but IP limit still applies
    if user:
        account_allowed, account_retry_after = check_account_lockout(user.id)
        if not account_allowed:
            # Record this attempt for IP tracking
            record_ip_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Invalid credentials",
                headers={"Retry-After": str(account_retry_after)}
            )
    
    # STEP 4: Validate credentials
    # If user doesn't exist, treat as invalid credentials (don't reveal)
    if not user:
        # Record failed attempt for IP tracking
        record_ip_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # Check if account is active
    if not user.is_active:
        # Record failed attempt for IP tracking
        record_ip_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid credentials"
        )

    # Check password
    if not verify_password(request.password, user.hashed_password):
        # Record failed attempt for account lockout escalation and IP tracking
        record_failed_login(user.id)
        record_ip_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # STEP 5: Successful login - reset account lockout
    reset_account_lockout(user.id)
    
    # Log successful attempt in database (for audit)
    db.add(LoginAttempt(
        email=normalized_email,
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
        user_email=user.email,
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
    payload = decode_token(request.refresh_token, token_type="refresh")

    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Check token in DB
    rt = db.query(RefreshToken).filter(
        RefreshToken.token == request.refresh_token,
        RefreshToken.revoked == False
    ).first()

    if not rt or rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # Check if user exists and is active
    user = db.query(User).filter(
        User.id == rt.user_id,
        User.is_active == True
    ).first()
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
        User.email == email_normalized
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
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """View recent login attempts (for security monitoring).
    
    SECURITY: Restricted to ADMIN role only (CWE-639 IDOR remediation).
    """
    attempts = db.query(LoginAttempt).order_by(
        desc(LoginAttempt.attempted_at)
    ).offset(offset).limit(limit).all()

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
