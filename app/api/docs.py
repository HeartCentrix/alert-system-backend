import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, UserRole
from app.core.security import verify_password
from app.services.rate_limiter import record_ip_failure, is_ip_locked

logger = logging.getLogger(__name__)

security = HTTPBasic()

# Rate limit constants for docs auth
# More aggressive than login since docs access is rare and admin-only
DOCS_AUTH_MAX_FAILURES = 5  # Lock after 5 failed attempts
DOCS_AUTH_LOCKOUT_SECONDS = 900  # 15 minute lockout


async def get_admin_or_super_admin_user(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """
    HTTP Basic Auth for admin/super admin access to docs.
    Browser shows native login popup.
    
    Security:
    - IP-based rate limiting via shared Redis counters (same as login)
    - Failed attempts contribute to global IP lockout
    - Timing-safe password comparison via bcrypt
    
    Allowed roles: SUPER_ADMIN, ADMIN
    """
    # Extract client IP
    client_ip = request.client.host if request.client else "unknown"

    # Check if IP is already locked out (shared with login rate limiter)
    if await is_ip_locked(client_ip):
        logger.warning(f"Docs auth blocked — IP {client_ip} is locked out")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Please try again later.",
        )

    user = db.query(User).filter(User.email == credentials.username).first()

    if not user:
        # Record failure for IP rate limiting even if user doesn't exist
        await record_ip_failure(client_ip)
        logger.warning(f"Docs auth failed — unknown email from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not verify_password(credentials.password, user.hashed_password):
        await record_ip_failure(client_ip)
        logger.warning(f"Docs auth failed — wrong password for {credentials.username} from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Check role AFTER password verification (don't reveal which part failed)
    user_role = str(user.role.value) if hasattr(user.role, 'value') else str(user.role)
    if user_role.lower() not in ["super_admin", "admin"]:
        # Don't record as IP failure — valid user, just wrong role
        logger.warning(f"Docs auth denied — user {credentials.username} has role {user_role}, needs admin")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or Super Admin access required",
        )

    return user


router = APIRouter()


@router.get("/docs", include_in_schema=False)
async def swagger_docs(current_user: User = Depends(get_admin_or_super_admin_user)):
    """Protected Swagger UI — requires admin/super admin HTTP Basic Auth."""
    return get_swagger_ui_html(
        openapi_url="/api/v1/openapi.json",
        title="TM Alert API - Swagger UI",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@router.get("/redoc", include_in_schema=False)
async def redoc_docs(current_user: User = Depends(get_admin_or_super_admin_user)):
    """Protected ReDoc — requires admin/super admin HTTP Basic Auth."""
    return get_redoc_html(
        openapi_url="/api/v1/openapi.json",
        title="TM Alert API - ReDoc",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@router.get("/openapi.json", include_in_schema=False)
async def openapi(current_user: User = Depends(get_admin_or_super_admin_user)):
    """Protected OpenAPI schema — requires admin/super admin HTTP Basic Auth."""
    from app.main import app
    return get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
        servers=app.servers,
    )
