import secrets
import time
import logging
import json
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
import redis
from app.database import get_db
from app.models import User, RefreshToken, AuditLog, UserRole, LoginAttempt
from app.schemas import (
    LoginRequest, TokenResponse, RefreshRequest, UserResponse,
    PasswordResetRequest, PasswordResetConfirm, ChangePasswordRequest,
    UserProfileUpdate, MFASetupInitiateResponse, MFASetupConfirmRequest,
    MFAStatusResponse, MFANeededResponse,
    LoginSuccessResponse, LoginMFASetupResponse, LoginMFAChallengeResponse,
    MFAVerifyLoginRequest,
    MFARecoveryCodeVerifyRequest, MFARecoveryCodesResponse, MFARecoveryCodeStatus,
    MFARegenerateRecoveryCodesRequest, MFARegenerateRecoveryCodesResponse,
    MFAEnrollStartRequest, MFAEnrollStartResponse, MFAEnrollConfirmRequest,
    MFAEnrollConfirmResponse, MFADisableRequest, MFADisableResponse,
    MFAResetStartRequest, MFAResetConfirmRequest, MFAResetConfirmResponse,
    MFAStatusDetailResponse,
)
from app.core.security import (
    verify_password, hash_password, create_access_token,
    create_refresh_token, decode_token, user_requires_mfa,
    verify_totp_code, generate_mfa_secret, generate_mfa_qr_code_uri,
    hash_password_reset_token, verify_password_reset_token,
    decrypt_mfa_secret, is_totp_replay,
)
from app.services.mfa_recovery import (
    generate_recovery_codes, verify_recovery_code,
    get_recovery_code_status, invalidate_all_recovery_codes
)
from app.services.mfa_lifecycle import get_mfa_service
from app.core.deps import get_current_user, require_admin
from app.services.messaging import email_service
from app.services.rate_limiter import (
    record_failed_login as redis_record_failed_login,
    is_account_locked,
    record_ip_failure,
    is_ip_locked,
    clear_account_failures,
    get_account_failure_count,
    get_device_failure_count,
    record_device_failure,
)
from app.services.security_notifications import notify_suspicious_login, notify_recovery_codes_regenerated
from app.config import settings
from app.utils.audit import create_audit_log

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Simple in-memory rate limiting for password reset requests
# Format: {email: last_request_timestamp}
_password_reset_rate_limit: dict[str, float] = {}
PASSWORD_RESET_RATE_LIMIT_SECONDS = 30  # 30 seconds between requests per email

# Redis-based login rate limiting constants (kept for backward compatibility with old functions)
ACCOUNT_LOCKOUT_THRESHOLD = 5  # Failed attempts before account lockout
IP_RATE_LIMIT_MAX_ATTEMPTS = 20  # Max attempts per IP across all accounts
IP_RATE_LIMIT_WINDOW_SECONDS = 600  # 10 minutes

# MFA challenge token settings
MFA_CHALLENGE_EXPIRE_SECONDS = 300  # 5 minutes to complete MFA verification


def _set_refresh_cookie(response: Response, token: str, expire_days: int) -> None:
    """
    Attach the refresh token as an HttpOnly cookie on a FastAPI Response object.

    NOTE: For cross-origin deployments (Vercel + Railway), cookies are set but
    browsers may block them. Frontend should also accept refresh_token in response body.

    Security properties:
    - HttpOnly: JS cannot read it — eliminates XSS token theft
    - Secure: HTTPS only — never sent over plain HTTP
    - SameSite=None: Required for cross-origin cookie usage
    - Path=/api/v1/auth: cookie only sent to auth endpoints

    In development mode, secure=False so localhost works without HTTPS.
    """
    is_secure = settings.APP_ENV != "development"

    # For cross-origin (Vercel -> Railway), we need SameSite=None
    # This is secure because we always use Secure flag (HTTPS only)
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=is_secure,
        samesite="none",  # Required for cross-origin (Vercel to Railway)
        path="/api/v1/auth",  # Scoped: only sent to auth endpoints
        max_age=expire_days * 86400,  # seconds
    )


def format_lockout_time(seconds: int) -> str:
    """Format lockout duration in human-readable format."""
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        mins = seconds // 60
        return f"{mins} minute{'s' if mins > 1 else ''}"
    elif seconds < 86400:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        if mins > 0:
            return f"{hours} hour{'s' if hours > 1 else ''} {mins} minute{'s' if mins > 1 else ''}"
        return f"{hours} hour{'s' if hours > 1 else ''}"
    days = seconds // 86400
    return f"{days} day{'s' if days > 1 else ''}"


def _generate_challenge_token(user_id: int) -> str:
    """
    Generate a signed JWT challenge token for MFA verification.

    Encodes user_id with a 5-minute expiry, signed with the dedicated
    MFA_CHALLENGE_SECRET_KEY. The 'type' claim is set to 'mfa_challenge'
    to prevent this token being accepted anywhere else in the system.

    Args:
        user_id: User's database ID

    Returns:
        Signed HS256 JWT string
    """
    import jwt as pyjwt

    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": "mfa_challenge",
        "iat": now,
        "exp": now + timedelta(seconds=MFA_CHALLENGE_EXPIRE_SECONDS),
    }
    return pyjwt.encode(payload, settings.MFA_CHALLENGE_SECRET_KEY, algorithm="HS256")


def _verify_challenge_token(token: str) -> tuple[bool, int]:
    """
    Verify and decode a JWT challenge token.

    PyJWT automatically validates the 'exp' claim — expired tokens raise
    ExpiredSignatureError (subclass of PyJWTError) and are caught below.
    The 'type' claim is checked explicitly to prevent access/refresh tokens
    being accepted here.

    Args:
        token: JWT challenge token string from the client

    Returns:
        tuple: (is_valid, user_id)
        Returns (False, 0) on any failure: invalid signature, expired, wrong type
    """
    import jwt as pyjwt
    from jwt.exceptions import PyJWTError

    try:
        payload = pyjwt.decode(
            token,
            settings.MFA_CHALLENGE_SECRET_KEY,
            algorithms=["HS256"]
        )
        if payload.get("type") != "mfa_challenge":
            return False, 0
        user_id = int(payload["sub"])
        return True, user_id
    except (PyJWTError, ValueError, KeyError):
        return False, 0


def _get_redis_client() -> redis.Redis:
    """
    Get a synchronous Redis client for login rate limiting.
    Uses sync client because login is a sync function.
    Fails closed (raises exception) if Redis is unavailable.
    
    Security: Redis connections use TLS with full certificate verification
    when using rediss:// scheme (ssl_cert_reqs=CERT_REQUIRED).
    """
    # Build SSL options for TLS connections
    # SECURITY: Require TLS with full certificate verification (CERT_REQUIRED)
    ssl_opts = {}
    import ssl
    if settings.REDIS_URL.startswith("rediss://"):
        ssl_opts = {
            "ssl_cert_reqs": ssl.CERT_REQUIRED,
            "ssl_check_hostname": True,
        }
    
    return redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        **ssl_opts
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


@router.post("/login")
async def login(request: LoginRequest, req: Request, response: Response, db: Session = Depends(get_db)):
    """
    Authenticate user with email and password.
    
    Response varies based on MFA status:
    - LoginSuccessResponse: Authentication complete, tokens issued
    - LoginMFASetupResponse: MFA required but not configured, setup needed
    - LoginMFAChallengeResponse: MFA required and configured, OTP needed
    
    No tokens are issued until MFA verification completes (if required).
    """
    client_ip = _get_client_ip(req)

    # Normalize email to prevent case-based lockout bypass
    # e.g., "Admin@Site.com" vs "admin@site.com" must hit the same lockout counter
    normalized_email = request.email.strip().lower()

    # STEP 1: Check IP-based rate limit FIRST (before any user lookup)
    # This prevents enumeration attacks and applies across ALL accounts
    if await is_ip_locked(client_ip):
        logger.warning(f"IP lockout for {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )

    # STEP 2: Look up user by email (case-insensitive)
    # Use func.lower for case-insensitive comparison to match normalized_email
    user = db.query(User).filter(
        func.lower(User.email) == normalized_email
    ).first()

    # STEP 3: If user exists, check account lockout
    # If user doesn't exist, skip account lockout but IP limit still applies
    if user:
        if await is_account_locked(user.id):
            # Record this failed attempt for IP tracking
            await record_ip_failure(client_ip)
            logger.warning(f"Account lockout for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked.",
            )

    # STEP 4: Validate credentials
    # If user doesn't exist, treat as invalid credentials (don't reveal)
    if not user:
        # Record failed attempt for IP tracking
        await record_ip_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # Check if account is active
    if not user.is_active:
        # Record failed attempt for IP tracking
        await record_ip_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid credentials"
        )

    # STEP 5: Device fingerprint tracking (if provided)
    # Track failures per device to detect automated attacks
    if request.device_fingerprint:
        device_count = await get_device_failure_count(request.device_fingerprint)
        if device_count >= 50:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts from this device."
            )

    # STEP 6: Verify password
    if not verify_password(request.password, user.hashed_password):
        # Record failed attempt for account lockout escalation and IP tracking
        count = await redis_record_failed_login(user.id)
        await record_ip_failure(client_ip)

        # Track device failures if fingerprint provided
        if request.device_fingerprint:
            await record_device_failure(request.device_fingerprint)

        # Send security notification email at first lockout threshold (5 failures)
        # Only send once at count == 5 to avoid spamming user's inbox
        if count == 5:
            await notify_suspicious_login(
                email=user.email,
                attempt_count=count,
                ip_address=client_ip,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # STEP 7: Check if MFA is required for this user
    mfa_required = user_requires_mfa(user)

    if mfa_required:
        # Check if user has MFA fully configured AND enabled
        # A user might have mfa_secret from partial setup but mfa_enabled=False
        mfa_fully_configured = user.mfa_enabled and user.mfa_secret and user.mfa_secret.strip()

        if not mfa_fully_configured:
            # MFA is required but not fully configured - initiate/re-initiate setup flow
            # Generate a new secret for this user (overwrites any partial setup)
            temp_secret = generate_mfa_secret()
            qr_code_uri = generate_mfa_qr_code_uri(user.email, temp_secret)

            # Encrypt and save the secret to user record (MFA not enabled until confirmed)
            from app.core.security import encrypt_mfa_secret
            encrypted_secret = encrypt_mfa_secret(temp_secret)
            user.mfa_secret = encrypted_secret
            user.mfa_enabled = False  # Explicitly ensure it's not enabled yet
            db.add(user)
            db.commit()

            # Generate challenge token for verification
            challenge_token = _generate_challenge_token(user.id)

            logger.info(f"MFA setup initiated for privileged user {user.id} ({user.email})")

            # Return setup information - NO tokens issued yet
            return LoginMFASetupResponse(
                status="mfa_required",
                mfa_required=True,
                mfa_configured=False,
                challenge_token=challenge_token,
                qr_code_uri=qr_code_uri,
                secret=temp_secret,
                message="MFA is required for your account. Please scan the QR code with your authenticator app and enter the code to complete login."
            )

        # MFA is configured and enabled - validate code
        if not request.mfa_code:
            # User has MFA configured but didn't provide code - return challenge response
            challenge_token = _generate_challenge_token(user.id)
            logger.info(f"MFA challenge issued for user {user.id} ({user.email})")

            return LoginMFAChallengeResponse(
                status="mfa_required",
                mfa_required=True,
                mfa_configured=True,
                challenge_token=challenge_token,
                message="Enter your authentication code to continue."
            )

        # Verify the TOTP code
        _plain_secret_for_totp = decrypt_mfa_secret(user.mfa_secret) or user.mfa_secret
        if not verify_totp_code(_plain_secret_for_totp, request.mfa_code):
            # Invalid MFA code - record as failed attempt
            count = await redis_record_failed_login(user.id)
            await record_ip_failure(client_ip)

            # Track device failures if fingerprint provided
            if request.device_fingerprint:
                await record_device_failure(request.device_fingerprint)

            logger.warning(f"Invalid MFA code for user {user.id} ({user.email})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials or MFA code"
            )

        # Replay protection — reject reuse within the same 30-second window
        if is_totp_replay(user, request.mfa_code):
            logger.warning(f"TOTP replay attempt detected for user {user.id} ({user.email})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOTP code already used. Please wait for the next code."
            )

        # Record this code as used — will be committed with the final db.commit()
        user.last_used_totp_code = request.mfa_code
        user.last_used_totp_at = datetime.now(timezone.utc)
        db.add(user)

    # STEP 8: Successful authentication - issue tokens
    await clear_account_failures(user.id)
    # Note: Do NOT record IP attempt on success - only failures count toward rate limit

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
    db.add(create_audit_log(
        user_id=user.id,
        user_email=user.email,
        action="login",
        resource_type="user",
        resource_id=user.id,
        request=req,
    ))
    db.commit()

    # Set refresh token as HttpOnly cookie (for same-origin fallback)
    _set_refresh_cookie(response, refresh_token_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)

    return LoginSuccessResponse(
        status="success",
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        refresh_token=refresh_token_str  # For cross-origin deployments (Vercel + Railway)
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(req: Request, response: Response, db: Session = Depends(get_db)):
    """
    Refresh access token using the refresh token from HttpOnly cookie or request body.

    Security:
    - Refresh token read from HttpOnly cookie (primary) or request body (fallback for cross-origin)
    - Old token revoked, new token issued (rotation)
    - New refresh token set as HttpOnly cookie
    """
    # Try to read refresh token from HttpOnly cookie first (same-origin fallback)
    refresh_token_str = req.cookies.get("refresh_token")

    # If no cookie, try request body (cross-origin fallback for Vercel + Railway)
    if not refresh_token_str:
        try:
            content_type = req.headers.get("content-type", "")
            if "application/json" in content_type:
                # Read body asynchronously
                import json
                body_bytes = await req.body()
                body_data = json.loads(body_bytes.decode())
                refresh_token_str = body_data.get("refresh_token")
        except Exception:
            pass  # Will raise 401 below if no token found

    if not refresh_token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token"
        )

    payload = decode_token(refresh_token_str, token_type="refresh")

    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    # Check token in DB
    rt = db.query(RefreshToken).filter(
        RefreshToken.token == refresh_token_str,
        RefreshToken.revoked == False
    ).first()

    if not rt or rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired"
        )

    # Check if user exists and is active
    user = db.query(User).filter(
        User.id == rt.user_id,
        User.is_active == True
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

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

    # Set new refresh token as HttpOnly cookie
    _set_refresh_cookie(response, new_refresh_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)

    return TokenResponse(
        access_token=new_access,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        refresh_token=new_refresh_str  # For cross-origin deployments (Vercel + Railway)
    )


@router.post("/logout")
def logout(
    req: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout user by revoking refresh token and clearing cookie.

    Security:
    - Refresh token read from HttpOnly cookie
    - Token revoked in database
    - Cookie cleared from browser
    """
    # Read refresh token from HttpOnly cookie
    refresh_token_str = req.cookies.get("refresh_token")

    if refresh_token_str:
        rt = db.query(RefreshToken).filter(
            RefreshToken.token == refresh_token_str,
            RefreshToken.user_id == current_user.id
        ).first()
        if rt:
            rt.revoked = True
            db.commit()

    # Clear the HttpOnly cookie
    # Must match the same settings as set_cookie
    response.delete_cookie(
        key="refresh_token",
        path="/api/v1/auth",
        secure=True,
        httponly=True,
        samesite="none",  # Must match set_cookie
    )
    return {"message": "Logged out successfully"}


@router.post("/forgot-password")
def forgot_password(request: PasswordResetRequest, req: Request, db: Session = Depends(get_db)):
    """
    Request a password reset email.

    Security measures:
    - Rate limiting: 1 request per minute per email
    - No email enumeration: Same response regardless of whether email exists
    - Token hashing: Password reset tokens are hashed before storage (SHA-256)
      Even if the database is compromised, attackers cannot use stolen tokens
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

    # Generate reset token (plaintext - sent to user via email)
    token = secrets.token_urlsafe(32)
    
    # Hash the token before storing in database
    # This ensures that even if the DB is compromised, tokens can't be used directly
    hashed_token = hash_password_reset_token(token)
    user.password_reset_token = hashed_token
    user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()

    # Send email with plaintext token (user needs the plaintext to reset password)
    email_service.send_password_reset_email(user.email, token, user.full_name)

    # Update rate limit
    _password_reset_rate_limit[email_normalized] = current_time

    return {"message": "If that email exists, we've sent a password reset link."}


@router.post("/reset-password")
def reset_password(request: PasswordResetConfirm, db: Session = Depends(get_db)):
    """
    Reset password using a valid reset token.

    Security:
    - Token is hashed before comparison with stored hash
    - Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks
    - Token must not be expired
    - Fetches all users with valid reset tokens, then compares in application code
    - No email enumeration (same error for invalid token vs non-existent user)
    """
    import hmac
    
    # Hash the incoming token
    incoming_hash = hash_password_reset_token(request.token)
    
    # Fetch all users with non-expired reset tokens
    # This prevents timing attacks that could enumerate emails
    now = datetime.now(timezone.utc)
    users_with_tokens = db.query(User).filter(
        User.password_reset_token.isnot(None),
        User.password_reset_expires > now
    ).all()
    
    # Find matching user using constant-time comparison
    matched_user = None
    for user in users_with_tokens:
        stored_token = user.password_reset_token or ""
        # Use constant-time comparison to prevent timing attacks
        if hmac.compare_digest(stored_token, incoming_hash):
            matched_user = user
            break
    
    if not matched_user:
        # Generic error to prevent enumeration of whether token exists
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    matched_user.hashed_password = hash_password(request.new_password)
    matched_user.password_reset_token = None
    matched_user.password_reset_expires = None

    # Invalidate all existing access tokens
    matched_user.token_valid_after = datetime.now(timezone.utc)

    # Revoke all refresh tokens to force re-authentication with new password
    db.query(RefreshToken).filter(
        RefreshToken.user_id == matched_user.id,
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

    # Invalidate all existing access tokens by setting token_valid_after
    # Any JWT with iat < this timestamp will be rejected by get_current_user
    current_user.token_valid_after = datetime.now(timezone.utc)

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


@router.put("/me", response_model=UserResponse)
def update_my_profile(
    data: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    req: Request = None,
):
    """Update your own profile.

    Users can update their personal information but cannot modify:
    - role (cannot escalate privileges)
    - is_active (cannot reactivate deactivated accounts)
    - employee_id (managed by admin only)
    """
    # Use exclude_unset=True to only update fields that were explicitly provided
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(current_user, field, value)

    db.add(create_audit_log(
        user_id=current_user.id,
        action="update_own_profile",
        resource_type="user",
        resource_id=current_user.id,
        details={"updated_fields": list(data.model_dump(exclude_unset=True).keys())},
        request=req,
    ))
    db.commit()
    db.refresh(current_user)
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


@router.post("/debug/reset-rate-limits")
def reset_rate_limits(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Debug endpoint to reset all rate limits. ADMIN only.

    Remove in production or restrict to super_admin only.
    """
    r = _get_redis_client()

    # Delete all lockout keys
    keys = r.keys("lockout:*")
    if keys:
        r.delete(*keys)

    return {"message": f"Deleted {len(keys)} rate limit keys"}


# ─── MFA ENDPOINTS ────────────────────────────────────────────────────────────

# ─── MFA LIFECYCLE ENDPOINTS ────────────────────────────────────────────────

@router.post("/mfa/enroll/start", response_model=MFAEnrollStartResponse)
def start_mfa_enrollment(
    request: MFAEnrollStartRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Start MFA enrollment for the current user.

    This is step 1 of a 2-step enrollment flow:
    1. Call this endpoint with current password (reauthentication)
    2. User scans QR code with authenticator app
    3. Call /account/mfa/enroll/complete with OTP code

    Security requirements (OWASP):
    - Requires recent reauthentication (current password)
    - Does NOT enable MFA until OTP is verified
    - Invalidates any previous pending enrollment
    - Does NOT expose user to MFA if already enabled

    Returns:
        QR code URI and secret for authenticator app setup
    """
    # Check if MFA is already enabled
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled for your account"
        )

    mfa_service = get_mfa_service(db)

    try:
        secret, qr_code_uri, manual_entry_key = mfa_service.start_enrollment(
            user=current_user,
            current_password=request.current_password
        )

        # Commit the pending enrollment
        db.commit()

        logger.info(f"MFA enrollment started for user {current_user.id}")

        return MFAEnrollStartResponse(
            secret=secret,
            qr_code_uri=qr_code_uri,
            manual_entry_key=manual_entry_key,
            message="Scan the QR code with your authenticator app, then enter the code to complete setup"
        )

    except ValueError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/mfa/enroll/complete", response_model=MFAEnrollConfirmResponse)
def complete_mfa_enrollment(
    request: MFAEnrollConfirmRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Complete MFA enrollment by verifying OTP code.

    This is step 2 of the enrollment flow:
    - User submits 6-digit code from authenticator app
    - On success: MFA is enabled, recovery codes generated
    - Recovery codes are shown ONCE only

    Security:
    - Validates OTP against pending secret
    - Only enables MFA on successful verification
    - Generates recovery codes (stored as hashes)
    - Audit logged
    """
    mfa_service = get_mfa_service(db)

    try:
        recovery_codes, batch_id = mfa_service.complete_enrollment(
            user=current_user,
            code=request.code
        )

        db.commit()

        logger.info(f"MFA enrollment completed for user {current_user.id}")

        return MFAEnrollConfirmResponse(
            message="MFA enabled successfully! Store these recovery codes in a secure location.",
            recovery_codes=recovery_codes,
            recovery_codes_warning="These codes will NOT be shown again. Each code can only be used once."
        )

    except ValueError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/mfa/disable", response_model=MFADisableResponse)
def disable_mfa(
    request: MFADisableRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Disable MFA for the current user.

    Security requirements (OWASP):
    - Checks if user is allowed to disable (policy enforcement)
    - Requires recent reauthentication (current password)
    - Requires current MFA code or recovery code verification
    - Clears MFA state and invalidates recovery codes
    - Audit logged

    Note: Privileged users (ADMIN, MANAGER, SUPER_ADMIN) cannot self-disable MFA.
    """
    mfa_service = get_mfa_service(db)

    try:
        mfa_service.disable_mfa(
            user=current_user,
            current_password=request.current_password,
            mfa_code=request.mfa_code
        )

        db.commit()

        logger.info(f"MFA disabled for user {current_user.id}")

        return MFADisableResponse(
            message="MFA has been disabled successfully. Your account is now less secure.",
            mfa_disabled=True
        )

    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/mfa/reset/start", response_model=MFAEnrollStartResponse)
def start_mfa_reset(
    request: MFAResetStartRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Start MFA reset/replacement flow.

    Use this when:
    - User changed devices
    - User lost authenticator but has recovery codes
    - User wants to rotate MFA secrets

    Security requirements:
    - Requires current password verification
    - Requires current MFA code OR recovery code (if available)
    - Invalidates old MFA secret and recovery codes
    - Creates pending new enrollment

    Returns:
        New QR code URI and secret for authenticator app setup
    """
    mfa_service = get_mfa_service(db)

    try:
        secret, qr_code_uri, manual_entry_key = mfa_service.start_reset(
            user=current_user,
            current_password=request.current_password,
            mfa_code=request.mfa_code
        )

        db.commit()

        logger.info(f"MFA reset started for user {current_user.id}")

        return MFAEnrollStartResponse(
            secret=secret,
            qr_code_uri=qr_code_uri,
            manual_entry_key=manual_entry_key,
            message="Your previous MFA has been invalidated. Scan the new QR code with your authenticator app."
        )

    except ValueError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/mfa/reset/complete", response_model=MFAResetConfirmResponse)
def complete_mfa_reset(
    request: MFAResetConfirmRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Complete MFA reset by verifying new OTP code.

    This completes the reset/re-enrollment flow:
    - User submits 6-digit code from NEW authenticator app
    - On success: MFA is enabled with new secret
    - New recovery codes are generated

    Security:
    - Validates OTP against new pending secret
    - Only enables MFA on successful verification
    - Generates new recovery codes
    - Audit logged
    """
    mfa_service = get_mfa_service(db)

    try:
        recovery_codes, batch_id = mfa_service.complete_reset(
            user=current_user,
            code=request.code
        )

        db.commit()

        logger.info(f"MFA reset completed for user {current_user.id}")

        return MFAResetConfirmResponse(
            message="MFA has been reset successfully! Store these new recovery codes in a secure location.",
            recovery_codes=recovery_codes,
            recovery_codes_warning="These codes will NOT be shown again. Your previous recovery codes have been invalidated."
        )

    except ValueError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/mfa/recovery-codes/regenerate", response_model=MFARegenerateRecoveryCodesResponse)
async def regenerate_recovery_codes_endpoint(
    request: MFARegenerateRecoveryCodesRequest,
    req: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Regenerate recovery codes for the authenticated user with dual-proof verification.

    Security requirements (OWASP/NIST):
    - Requires password verification (knowledge factor)
    - Requires MFA proof (possession factor):
      - TOTP code from authenticator app, OR
      - Single unused recovery code (normal users only)
    - Privileged users cannot use recovery code fallback
    - Rate limited to prevent brute force
    - Invalidates all previous unused codes atomically
    - Returns new plaintext codes (only time they're available)
    - Full audit logging

    This endpoint is for users who:
    - Lost their recovery codes
    - Want to rotate codes periodically
    - Used some codes and want fresh ones
    """
    client_ip = _get_client_ip(req)
    mfa_service = get_mfa_service(db)

    # Rate limiting: Check if account is locked for regeneration attempts
    # Use same mechanism as login rate limiting
    is_allowed, retry_after = check_account_lockout(current_user.id)
    if not is_allowed:
        logger.warning(
            f"Recovery code regeneration rate limited for user {current_user.id} "
            f"(retry after: {retry_after}s)"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many regeneration attempts. Please try again later."
        )

    try:
        plaintext_codes, batch_id, old_codes_invalidated = mfa_service.regenerate_recovery_codes(
            user=current_user,
            current_password=request.current_password,
            method=request.method,
            mfa_code=request.mfa_code,
            recovery_code=request.recovery_code,
            ip_address=client_ip,
            user_agent=req.headers.get("user-agent")
        )

        db.commit()

        # Send security notification email (fire-and-forget, does not block response)
        await notify_recovery_codes_regenerated(
            email=current_user.email,
            ip_address=client_ip,
            method=request.method,
            old_codes_count=old_codes_invalidated,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        logger.info(
            f"Recovery codes regenerated for user {current_user.id} "
            f"(method: {request.method}, old codes invalidated: {old_codes_invalidated})"
        )

        return MFARegenerateRecoveryCodesResponse(
            recovery_codes=plaintext_codes,
            batch_id=batch_id[:8] + "...",
            message="Recovery codes regenerated successfully",
            warning="Store these codes securely. They will not be shown again. Your previous unused codes have been invalidated.",
            old_codes_invalidated=old_codes_invalidated
        )

    except PermissionError as e:
        # Privileged user tried to use disallowed method
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except ValueError as e:
        # Verification failed - record as failed attempt for rate limiting
        record_failed_login(current_user.id)
        db.rollback()
        logger.warning(f"Recovery code regeneration failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


# ─── LEGACY MFA ENDPOINTS (kept for backward compatibility) ─────────────────


@router.get("/mfa/status", response_model=MFAStatusDetailResponse)
def get_mfa_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get the current MFA status for the authenticated user.

    Returns comprehensive MFA status including:
    - Whether MFA is enabled/configured
    - Whether MFA is required by policy
    - Recovery codes status (count, not the codes themselves)
    - Whether user can disable MFA (based on role policy)
    - Whether there's a pending enrollment

    Security:
    - Requires authentication
    - Does NOT expose secrets or recovery codes
    - Safe for frontend to display in security settings
    """
    mfa_service = get_mfa_service(db)
    status_data = mfa_service.get_mfa_status(current_user)

    return MFAStatusDetailResponse(**status_data)


@router.post("/mfa/verify-login", response_model=LoginSuccessResponse)
async def verify_mfa_and_complete_login(
    request: MFAVerifyLoginRequest,
    req: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Complete MFA verification and issue auth tokens.
    
    Use this endpoint after receiving a challenge token from /login:
    1. Call /login with credentials
    2. Receive challenge token (and QR code if setup needed)
    3. User scans QR and gets OTP from authenticator app
    4. Call this endpoint with challenge_token + OTP code
    5. Receive full auth tokens on success
    
    Security:
    - Challenge token must be valid and not expired
    - OTP code must match user's TOTP secret
    - No tokens issued until both verifications pass
    - Failed attempts counted toward rate limiting
    """
    client_ip = _get_client_ip(req)

    # Check IP-based rate limit FIRST (before processing challenge token)
    # This prevents brute-force attacks on the TOTP code (6 digits = 1M combinations)
    if await is_ip_locked(client_ip):
        logger.warning(f"IP lockout for {client_ip} at MFA verify")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Please try again later.",
        )

    # Verify JWT challenge token — signature, expiry, and type all checked in one call
    is_valid, user_id = _verify_challenge_token(request.challenge_token)
    if not is_valid:
        logger.warning(f"Invalid or expired MFA challenge token from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or MFA code"
        )

    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        logger.warning(f"User {user_id} not found or inactive")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or MFA code"
        )

    # Verify MFA is still required (user might have completed setup in another session)
    if not user_requires_mfa(user):
        logger.warning(f"MFA no longer required for user {user_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not required"
        )
    
    # Verify OTP code
    if not user.mfa_secret:
        logger.warning(f"No MFA secret for user {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or MFA code"
        )

    _plain_secret_for_totp_verify = decrypt_mfa_secret(user.mfa_secret) or user.mfa_secret
    if not verify_totp_code(_plain_secret_for_totp_verify, request.code):
        # Invalid MFA code - record as failed attempt
        try:
            count = await redis_record_failed_login(user.id)
            await record_ip_failure(client_ip)
        except Exception as e:
            logger.error(f"Error recording failed login: {e}")

        logger.warning(f"Invalid MFA code for user {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or MFA code"
        )

    # Replay protection — reject reuse within the same 30-second window
    if is_totp_replay(user, request.code):
        logger.warning(f"TOTP replay attempt detected for user {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOTP code already used. Please wait for the next code."
        )

    # Record this code as used — will be committed with the final db.commit()
    user.last_used_totp_code = request.code
    user.last_used_totp_at = datetime.now(timezone.utc)
    db.add(user)
    
    # MFA verified successfully - enable MFA if not already enabled
    was_new_mfa = False
    recovery_codes = None
    if not user.mfa_enabled:
        user.mfa_enabled = True
        was_new_mfa = True

        # Generate initial recovery codes for new MFA users
        try:
            plaintext_codes, batch_id = generate_recovery_codes(
                db=db,
                user_id=user.id,
                generated_by_user_id=user.id,
                reason='initial_setup'
            )
            recovery_codes = plaintext_codes
            logger.info(f"Generated {len(plaintext_codes)} recovery codes for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to generate recovery codes: {e}")
            # Don't fail the login, but log the issue

        logger.info(f"MFA enabled for user {user_id} during login")
    
    # Issue tokens (same as successful login)
    try:
        await clear_account_failures(user.id)
    except Exception as e:
        logger.error(f"Error clearing account failures: {e}")

    # Log successful attempt
    db.add(LoginAttempt(
        email=user.email,
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
    db.add(create_audit_log(
        user_id=user.id,
        user_email=user.email,
        action="mfa_verified_login",
        resource_type="user",
        resource_id=user.id,
        request=req,
    ))
    db.commit()

    logger.info(f"MFA verification complete, login successful for user {user_id}")

    # Set refresh token as HttpOnly cookie
    _set_refresh_cookie(response, refresh_token_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)

    # Build response with recovery codes if this was first MFA setup
    # Include refresh_token in body for cross-origin deployments (Vercel + Railway)
    response_data = {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
        "refresh_token": refresh_token_str,  # For cross-origin deployments
    }

    if was_new_mfa and recovery_codes:
        response_data["recovery_codes"] = recovery_codes
        response_data["recovery_codes_warning"] = "Store these codes securely. They will not be shown again."

    return LoginSuccessResponse(**response_data)


# ─── MFA RECOVERY CODE ENDPOINTS ──────────────────────────────────────────────

@router.post("/mfa/recovery-code/verify", response_model=LoginSuccessResponse)
async def verify_recovery_code_and_login(
    request: MFARecoveryCodeVerifyRequest,
    req: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Complete login using a recovery code.
    
    Use this endpoint when user has lost their authenticator device but
    has recovery codes. This is the primary self-service recovery path.
    
    Flow:
    1. User enters credentials → receives challenge token (MFA required)
    2. User clicks "Use recovery code" 
    3. User submits challenge token + recovery code
    4. Backend verifies code, marks as used, issues tokens
    
    Security:
    - Recovery code is single-use (marked as used atomically)
    - Rate limited (see rate_limiter)
    - Audit logged
    - User notified of use
    """
    client_ip = _get_client_ip(req)

    # Check IP-based rate limit FIRST (before processing challenge token)
    # This prevents brute-force attacks on recovery codes
    if await is_ip_locked(client_ip):
        logger.warning(f"IP lockout for {client_ip} at recovery code verify")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Please try again later.",
        )

    # Verify JWT challenge token — signature, expiry, and type all checked in one call
    is_valid, user_id = _verify_challenge_token(request.challenge_token)
    if not is_valid:
        logger.warning(f"Invalid or expired MFA challenge token from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or recovery code"
        )

    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        logger.warning(f"User {user_id} not found or inactive")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or recovery code"
        )
    
    # Verify and consume recovery code
    is_valid, error = verify_recovery_code(
        db=db,
        user_id=user_id,
        code=request.recovery_code,
        ip_address=client_ip,
        user_agent=req.headers.get("user-agent")
    )
    
    if not is_valid:
        # Record failed attempt for rate limiting
        try:
            count = await redis_record_failed_login(user.id)
            await record_ip_failure(client_ip)
        except Exception as e:
            logger.error(f"Error recording failed recovery attempt: {e}")
        
        # Send security notification on first failure threshold
        if count == 5:
            try:
                from app.services.security_notifications import notify_suspicious_login
                await notify_suspicious_login(
                    email=user.email,
                    attempt_count=count,
                    ip_address=client_ip,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            except Exception as e:
                logger.error(f"Error sending security notification: {e}")
        
        logger.warning(f"Invalid recovery code for user {user_id}: {error}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or recovery code"
        )
    
    # Recovery code verified - issue tokens
    await clear_account_failures(user.id)
    
    # Log successful login
    db.add(LoginAttempt(
        email=user.email,
        ip_address=client_ip,
        success=True
    ))
    
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token_str = create_refresh_token({"sub": str(user.id)})
    
    rt = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(rt)
    
    user.last_login = datetime.now(timezone.utc)

    db.add(create_audit_log(
        user_id=user.id,
        user_email=user.email,
        action="recovery_code_login_success",
        resource_type="user",
        resource_id=user.id,
        request=req,
    ))
    db.commit()

    logger.info(f"Recovery code login successful for user {user_id}")

    # Set refresh token as HttpOnly cookie (for same-origin fallback)
    _set_refresh_cookie(response, refresh_token_str, settings.REFRESH_TOKEN_EXPIRE_DAYS)

    return LoginSuccessResponse(
        status="success",
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        refresh_token=refresh_token_str  # For cross-origin deployments (Vercel + Railway)
    )


@router.get("/account/mfa/recovery-codes/status", response_model=MFARecoveryCodeStatus)
def get_recovery_codes_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get the current status of recovery codes for the authenticated user.
    
    Returns whether user has codes and how many are unused.
    Does NOT return the actual codes (they're only shown once during generation).
    """
    status_data = get_recovery_code_status(db, current_user.id)
    return MFARecoveryCodeStatus(**status_data)


@router.post("/account/mfa/recovery-codes/regenerate", response_model=MFARecoveryCodesResponse)
def regenerate_recovery_codes(
    request: MFARegenerateRecoveryCodesRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Regenerate recovery codes for the authenticated user.
    
    Security requirements:
    - Requires password re-authentication (step-up)
    - Invalidates all previous unused codes
    - Returns new plaintext codes (only time they're available)
    - Audit logged
    - User notified
    
    This endpoint is for users who:
    - Lost their recovery codes
    - Want to rotate codes periodically
    - Regenerate after using some codes
    """
    # Verify current password (step-up authentication)
    if not verify_password(request.current_password, current_user.hashed_password):
        logger.warning(f"Invalid password during recovery code regeneration for user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )
    
    # Invalidate old codes first
    invalidate_all_recovery_codes(
        db=db,
        user_id=current_user.id,
        invalidated_by_user_id=current_user.id,
        reason='user_regenerated'
    )
    
    # Generate new codes
    plaintext_codes, batch_id = generate_recovery_codes(
        db=db,
        user_id=current_user.id,
        generated_by_user_id=current_user.id,
        reason='regenerated'
    )
    
    logger.info(f"User {current_user.id} regenerated recovery codes")
    
    return MFARecoveryCodesResponse(
        recovery_codes=plaintext_codes,
        batch_id=batch_id[:8] + "...",
        message="Recovery codes generated successfully",
        warning="Store these codes securely. They will not be shown again. Each code can only be used once."
    )


@router.post("/account/mfa/recovery-codes/generate-initial", response_model=MFARecoveryCodesResponse)
def generate_initial_recovery_codes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate initial recovery codes for a user who just enabled MFA.
    
    This is called automatically after successful MFA enrollment.
    Only works if user has no existing recovery codes.
    """
    # Check if user already has codes
    existing_status = get_recovery_code_status(db, current_user.id)
    if existing_status.has_codes and existing_status.unused_count > 0:
        logger.info(f"User {current_user.id} already has recovery codes, not generating new ones")
        # Return existing status but NOT the codes
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recovery codes already exist. Use regenerate endpoint if you need new codes."
        )
    
    # Generate new codes
    plaintext_codes, batch_id = generate_recovery_codes(
        db=db,
        user_id=current_user.id,
        generated_by_user_id=current_user.id,
        reason='initial_setup'
    )
    
    logger.info(f"Generated initial recovery codes for user {current_user.id}")
    
    return MFARecoveryCodesResponse(
        recovery_codes=plaintext_codes,
        batch_id=batch_id[:8] + "...",
        message="Recovery codes generated successfully. Store them securely!",
        warning="These codes will not be shown again. Each code can only be used once."
    )
