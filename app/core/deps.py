"""
Dependency Injection and Authentication Helpers for FastAPI.

This module provides dependency injection functions for FastAPI routes,
handling authentication, authorization, and token validation.

Key Features:
- JWT token validation and payload extraction
- Role-based access control (RBAC) decorators
- Session validity checks against token_valid_after timestamp
- Token refresh logic

Security:
- Tokens are validated against SECRET_KEY
- Session validity checked against token_valid_after timestamp
- Role hierarchy enforced: SUPER_ADMIN > ADMIN > MANAGER > VIEWER

Usage:
    @router.get("/protected")
    def protected_route(current_user: Annotated[User, Depends(get_current_user)]):
        return {"user": current_user}

    @router.post("/admin-only")
    def admin_route(current_user: Annotated[User, Depends(require_admin)]):
        return {"admin_action": "success"}
"""
from datetime import datetime, timezone
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database import get_db
from app.core.security import decode_token
from app.models import User, UserRole
from sqlalchemy.exc import OperationalError
import logging

logger = logging.getLogger(__name__)

security = HTTPBearer()


def _validate_token_payload(payload: dict) -> str:
    """Extract and validate user_id from JWT payload.
    
    Args:
        payload: Decoded JWT payload containing 'sub' (user_id) and 'type'
        
    Returns:
        User ID from token subject
        
    Raises:
        HTTPException: 401 if token is invalid, expired, or wrong type
    """
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user_id


def _check_token_session_validity(user: User, payload: dict) -> None:
    """Reject tokens issued before the user's last password change.
    
    This invalidates all existing tokens when a user changes their password,
    forcing re-authentication on all devices.
    
    Args:
        user: User object from database
        payload: Decoded JWT payload containing 'iat' (issued at) timestamp
        
    Raises:
        HTTPException: 401 if session invalidated by password change
    """
    if user.token_valid_after is None:
        return
    token_iat = payload.get("iat")
    if token_iat is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again."
        )
    if isinstance(token_iat, (int, float)):
        issued_at = datetime.fromtimestamp(token_iat, tz=timezone.utc)
    else:
        issued_at = token_iat
    if issued_at < user.token_valid_after:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired due to password change. Please log in again."
        )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[Session, Depends(get_db)]
) -> User:
    """Extract and validate the current authenticated user from JWT token.
    
    This is the primary authentication dependency for protected routes.
    
    Flow:
    1. Decode JWT token from Authorization header
    2. Validate token payload and extract user_id
    3. Verify user exists and account is enabled (is_enabled)
    4. Check session validity against token_valid_after timestamp
    
    Note: Checks is_enabled (admin-controlled account status), NOT is_online
    (real-time presence via heartbeat).
    
    Args:
        credentials: HTTP Bearer token from Authorization header
        db: Database session
        
    Returns:
        Authenticated User object
        
    Raises:
        HTTPException: 401 if token invalid, expired, or user not found/disabled
    """
    token = credentials.credentials
    payload = decode_token(token, token_type="access")
    user_id = _validate_token_payload(payload)

    # Check account status (is_enabled), NOT online presence (is_online)
    # is_enabled = admin-controlled account status (enabled/disabled)
    # is_online = real-time presence via heartbeat (changes every 30s)
    user = db.query(User).filter(
        User.id == int(user_id),
        User.is_enabled == True
    ).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or account disabled")

    # Session invalidation: reject tokens issued before the last password change.
    # Note: wrapped in try-except for cases where column doesn't exist yet (migration).
    try:
        _check_token_session_validity(user, payload)
    except OperationalError as e:
        if "token_valid_after" in str(e):
            logger.warning(
                "token_valid_after column not found, skipping session validation. "
                "Run: alembic upgrade head"
            )
        else:
            raise

    return user


def require_roles(*roles: UserRole):
    """Create a dependency that requires specific roles for access.
    
    This is a factory function that creates role-based access control
    dependencies for routes.
    
    Args:
        *roles: Variable number of UserRole enums that are allowed
        
    Returns:
        Dependency function that checks user role
        
    Raises:
        HTTPException: 403 if user role not in allowed roles
        
    Example:
        @router.post("/admin-only")
        def admin_route(current_user: Annotated[User, Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN))]):
            return {"admin_action": "success"}
    """
    def checker(current_user: Annotated[User, Depends(get_current_user)]):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in roles]}"
            )
        return current_user
    return checker


# Pre-built role dependencies for common use cases
require_admin = require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
require_manager = require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER)
require_super_admin = require_roles(UserRole.SUPER_ADMIN)
