from datetime import datetime, timezone
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


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    payload = decode_token(token, token_type="access")

    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

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
    # token_valid_after is set when the user changes/resets their password.
    # If NULL, no restriction (user never changed password since feature was added).
    # Note: This check is wrapped in try-except to handle cases where the column
    # doesn't exist yet (during migration or in Celery workers before startup).
    try:
        if user.token_valid_after is not None:
            token_iat = payload.get("iat")
            if token_iat is not None:
                # iat can be a float (unix timestamp) or int — normalize to datetime
                if isinstance(token_iat, (int, float)):
                    issued_at = datetime.fromtimestamp(token_iat, tz=timezone.utc)
                else:
                    issued_at = token_iat

                if issued_at < user.token_valid_after:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session expired due to password change. Please log in again."
                    )
            # If token has no iat claim (old tokens before this feature),
            # and user HAS changed password, reject it — old tokens are untrusted
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired. Please log in again."
                )
    except OperationalError as e:
        # Column doesn't exist yet - log warning and skip validation
        # This can happen in Celery workers before main app startup completes
        if "token_valid_after" in str(e):
            logger.warning(
                "token_valid_after column not found, skipping session validation. "
                "Run: alembic upgrade head"
            )
        else:
            raise

    return user


def require_roles(*roles: UserRole):
    def checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in roles]}"
            )
        return current_user
    return checker


require_admin = require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN)
require_manager = require_roles(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER)
require_super_admin = require_roles(UserRole.SUPER_ADMIN)
