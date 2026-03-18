from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import logging
import os
import re
import secrets

# Request size limit constants (in bytes)
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB max request body size
MAX_JSON_SIZE = 1 * 1024 * 1024  # 1 MB max JSON payload

from sqlalchemy import text
from alembic import command
from alembic.config import Config
from app.config import settings
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.csrf import CSRFMiddleware
from sqlalchemy import text
from app.database import engine, Base, SessionLocal, ensure_column_exists, ensure_mfa_secret_column_expanded
from app.models import (
    User, UserRole, AlertChannel, Location, Group, NotificationTemplate,
    Incident, Notification, DeliveryLog, NotificationResponse, IncomingMessage,
    AuditLog, RefreshToken, LoginAttempt, UserLocation, UserLocationHistory
)
from app.core.security import hash_password
from app.core.location_cache import init_location_cache, close_location_cache
from app.core.deps import require_admin

# NOTE: HTTPS enforcement is handled by Railway's infrastructure layer.
# Railway automatically redirects HTTP→HTTPS at the proxy level and terminates SSL.
# Adding HTTPSRedirectMiddleware here would cause infinite redirect loops because
# Railway forwards requests to the app as HTTP after SSL termination.
# HSTS header is set by SecurityHeadersMiddleware for browser-side enforcement.
from app.logging_config import setup_logging
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.groups_locations_templates import (
    groups_router, locations_router, templates_router
)
from app.api.notifications import (
    notifications_router, incidents_router
)
from app.api.webhooks import router as webhooks_router
from app.api.dashboard import router as dashboard_router
from app.api.location_v2 import router as location_router
from app.api.location_audience import router as location_audience_router
from app.api.docs import router as docs_router

# Apply initial logging config (will be re-applied in lifespan after uvicorn's override)
setup_logging()
logger = logging.getLogger(__name__)


def ensure_alertchannel_enum():
    """Ensure 'web' value exists in alertchannel enum (PostgreSQL).

    Uses engine.begin() for DDL operations as required by SQLAlchemy 2.x.
    """
    try:
        with engine.begin() as conn:
            # Check if 'web' enum value exists
            result = conn.execute(
                text(
                    "SELECT EXISTS("
                    "SELECT 1 FROM pg_enum "
                    "WHERE enumlabel = 'web' "
                    "AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'alertchannel')"
                    ")"
                )
            ).scalar()

            if not result:
                conn.execute(text("ALTER TYPE alertchannel ADD VALUE IF NOT EXISTS 'web'"))
                logger.info("Added 'web' to alertchannel enum")
            else:
                logger.info("alertchannel enum already has 'web' value")
    except Exception as e:
        logger.error(f"Error ensuring alertchannel enum: {e}")


def _ensure_user_location_columns():
    """Add latitude/longitude columns to users table if they don't exist."""
    try:
        ensure_column_exists('users', 'latitude', 'DOUBLE PRECISION', nullable=True)
        ensure_column_exists('users', 'longitude', 'DOUBLE PRECISION', nullable=True)
    except Exception as e:
        logger.error(f"Error adding user location columns: {e}")


def _ensure_audit_logs_table():
    """Ensure audit_logs table exists with proper schema."""
    db = SessionLocal()
    try:
        # Check if table exists
        result = db.execute(
            text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_name = 'audit_logs'
            """)
        ).fetchone()
        
        if result:
            logger.info("audit_logs table already exists")
            return
        
        # Create audit_logs table
        db.execute(text("""
            CREATE TABLE audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                user_email VARCHAR(255),
                action VARCHAR(200) NOT NULL,
                resource_type VARCHAR(100),
                resource_id INTEGER,
                details JSONB,
                ip_address VARCHAR(45),
                user_agent VARCHAR(500),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.commit()
        logger.info("Created audit_logs table")
        
    except Exception as e:
        logger.error(f"Error ensuring audit_logs table: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def _ensure_audit_log_user_email():
    """Add user_email column to audit_logs table if it doesn't exist."""
    db = SessionLocal()
    try:
        result = db.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name='audit_logs' AND column_name='user_email'")
        ).fetchone()
        if not result:
            db.execute(text("ALTER TABLE audit_logs ADD COLUMN user_email VARCHAR(255)"))
            db.commit()
            logger.info("Added user_email column to audit_logs table")
        else:
            logger.info("audit_logs table already has user_email column")
    except Exception as e:
        logger.error(f"Error adding audit_logs user_email column: {e}")
        db.rollback()
    finally:
        db.close()


def _ensure_incoming_messages_user_email():
    """Add user_email column to incoming_messages table if it doesn't exist."""
    db = SessionLocal()
    try:
        result = db.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name='incoming_messages' AND column_name='user_email'")
        ).fetchone()
        if not result:
            db.execute(text("ALTER TABLE incoming_messages ADD COLUMN user_email VARCHAR(255)"))
            db.commit()
            logger.info("Added user_email column to incoming_messages table")
        else:
            logger.info("incoming_messages table already has user_email column")
    except Exception as e:
        logger.error(f"Error adding incoming_messages user_email column: {e}")
        db.rollback()
    finally:
        db.close()


def _ensure_delivery_log_user_email():
    """Add user_email column to delivery_logs and notification_responses tables if they don't exist."""
    db = SessionLocal()
    try:
        # Check delivery_logs
        result = db.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name='delivery_logs' AND column_name='user_email'")
        ).fetchone()
        if not result:
            db.execute(text("ALTER TABLE delivery_logs ADD COLUMN user_email VARCHAR(255)"))
            db.commit()
            logger.info("Added user_email column to delivery_logs table")
        else:
            logger.info("delivery_logs table already has user_email column")

        # Check notification_responses
        result = db.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name='notification_responses' AND column_name='user_email'")
        ).fetchone()
        if not result:
            db.execute(text("ALTER TABLE notification_responses ADD COLUMN user_email VARCHAR(255)"))
            db.commit()
            logger.info("Added user_email column to notification_responses table")
        else:
            logger.info("notification_responses table already has user_email column")
    except Exception as e:
        logger.error(f"Error adding delivery_log/user_email columns: {e}")
        db.rollback()
    finally:
        db.close()


def _ensure_notifications_deadline_escalated():
    """Add deadline_escalated column to notifications table if it doesn't exist."""
    ensure_column_exists('notifications', 'deadline_escalated', 'BOOLEAN', nullable=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup secret validation ─────────────────────────────────────────
    # Fail fast: refuse to start if critical signing keys are absent or weak.
    # An empty or short key would allow token forgery.
    _secret_errors = []
    if not settings.SECRET_KEY or len(settings.SECRET_KEY) < 32:
        _secret_errors.append("SECRET_KEY is missing or shorter than 32 characters")
    if not settings.REFRESH_SECRET_KEY or len(settings.REFRESH_SECRET_KEY) < 32:
        _secret_errors.append("REFRESH_SECRET_KEY is missing or shorter than 32 characters")
    if not settings.MFA_CHALLENGE_SECRET_KEY or len(settings.MFA_CHALLENGE_SECRET_KEY) < 32:
        _secret_errors.append("MFA_CHALLENGE_SECRET_KEY is missing or shorter than 32 characters")
    if _secret_errors:
        raise RuntimeError(
            "Application cannot start — critical secret key(s) not configured:\n" +
            "\n".join(f"  • {e}" for e in _secret_errors)
        )
    # ─────────────────────────────────────────────────────────────────────

    # Re-apply logging config AFTER uvicorn's dictConfig has run.
    # Without this, uvicorn overwrites our formatters/handlers on startup.
    setup_logging()
    
    # Initialize Redis cache for location autocomplete
    logger.info("Initializing location cache...")
    try:
        await init_location_cache(settings.REDIS_URL)
        logger.info("Location cache initialized")
    except Exception as e:
        logger.error(f"Failed to initialize location cache: {e}")

    # Migrations already run in start.sh before uvicorn starts
    # No need to run them again here

    # Ensure alertchannel enum has 'web' value
    logger.info("Ensuring alertchannel enum has 'web' value...")
    try:
        ensure_alertchannel_enum()
    except Exception as e:
        logger.error(f"Failed to ensure alertchannel enum: {e}")

    # Ensure User table has latitude/longitude columns
    try:
        _ensure_user_location_columns()
    except Exception as e:
        logger.error(f"Failed to ensure user location columns: {e}")

    # Ensure User table has token_valid_after column (session invalidation on password change)
    try:
        ensure_column_exists('users', 'token_valid_after', 'TIMESTAMP WITH TIME ZONE', nullable=True)
    except Exception as e:
        logger.error(f"Failed to ensure token_valid_after column: {e}")

    # Ensure mfa_secret column is expanded for Fernet encryption (VARCHAR(32) -> VARCHAR(255))
    try:
        ensure_mfa_secret_column_expanded()
    except Exception as e:
        logger.error(f"Failed to expand mfa_secret column: {e}")

    # Ensure audit_logs table has user_email column
    logger.info("Ensuring audit_logs table has user_email column...")
    try:
        _ensure_audit_log_user_email()
    except Exception as e:
        logger.error(f"Failed to ensure audit_logs user_email column: {e}")

    # Ensure delivery_logs and notification_responses tables have user_email column
    logger.info("Ensuring delivery_logs and notification_responses tables have user_email column...")
    try:
        _ensure_delivery_log_user_email()
    except Exception as e:
        logger.error(f"Failed to ensure delivery_logs/notification_responses user_email column: {e}")

    # Ensure incoming_messages table has user_email column
    logger.info("Ensuring incoming_messages table has user_email column...")
    try:
        _ensure_incoming_messages_user_email()
    except Exception as e:
        logger.error(f"Failed to ensure incoming_messages user_email column: {e}")

    # Ensure notifications table has deadline_escalated column
    logger.info("Ensuring notifications table has deadline_escalated column...")
    try:
        _ensure_notifications_deadline_escalated()
    except Exception as e:
        logger.error(f"Failed to ensure notifications deadline_escalated column: {e}")

    # Seed default super admin if no users exist
    try:
        db = SessionLocal()
        try:
            if db.query(User).count() == 0:
                # Generate secure random password
                bootstrap_pw = secrets.token_urlsafe(32)
                admin = User(
                    email="admin@tmalert.com",
                    hashed_password=hash_password(bootstrap_pw),
                    first_name="Super",
                    last_name="Admin",
                    role=UserRole.SUPER_ADMIN,
                    is_active=True,
                    force_password_change=True
                )
                db.add(admin)
                db.commit()
                # Write password to protected file (NOT stdout/logs)
                try:
                    with open("/run/secrets/bootstrap_pw", "w") as f:
                        f.write(bootstrap_pw)
                    logger.info("Default admin created: admin@tmalert.com (password written to /run/secrets/bootstrap_pw)")
                except (IOError, OSError):
                    # Fallback for environments without /run/secrets
                    logger.warning("Default admin created: admin@tmalert.com - retrieve password from secure logs on first boot only")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Failed to seed default admin: {e}")

    logger.info("Application startup complete")
    yield
    
    # Cleanup: close Redis cache connection
    logger.info("Closing location cache...")
    await close_location_cache()
    logger.info("Shutting down TM Alert")


app = FastAPI(
    title="TM Alert API",
    description="Emergency Notification System for Taylor Morrison",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,  # Disable default - using protected custom endpoint
    redoc_url=None,  # Disable default - using protected custom endpoint
    openapi_url=None  # Disable default - using protected custom endpoint
)

# ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

# CORS Configuration - Explicitly define allowed origins
# SECURITY: Never use "*" for allow_origins when allow_credentials=True
# This would expose users to CSRF attacks and credential theft

# Build allowed origins list from config with validation
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:5173",
    "https://alert-system-frontend-jq7u.vercel.app",
]

# Add production FRONTEND_URL if configured and not a wildcard
if settings.FRONTEND_URL:
    # Reject wildcard origins - security risk
    if settings.FRONTEND_URL == "*" or settings.FRONTEND_URL == "null":
        logger.error(
            f"CORS SECURITY ERROR: FRONTEND_URL='{settings.FRONTEND_URL}' is not allowed. "
            "Wildcard origins are prohibited when allow_credentials=True."
        )
    else:
        # Add if not already in list
        if settings.FRONTEND_URL not in allowed_origins:
            allowed_origins.append(settings.FRONTEND_URL)
            logger.info(f"Added FRONTEND_URL to CORS allowed origins: {settings.FRONTEND_URL}")

# Add Railway domain for dynamic deployments (supports migration between Railway accounts)
railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN")
if railway_domain:
    railway_url = f"https://{railway_domain}"
    if railway_url not in allowed_origins:
        allowed_origins.append(railway_url)
        logger.info(f"Added Railway domain to CORS allowed origins: {railway_url}")

# Allow Railway subdomain patterns for preview deployments and migrations
# This supports:
# - Railway preview deployments (pr-*.railway.app)
# - Migration between Railway accounts (different subdomains)
# - Multiple environments (staging, production) on different Railway subdomains
logger.info(f"CORS allowed origins: {allowed_origins}")
logger.info("CORS origin regex: Railway subdomains allowed for migration flexibility")

# Request ID — generates UUID per request for log correlation
app.add_middleware(RequestIDMiddleware)

# CSRF protection — double-submit cookie pattern
# Registered before CORS so it can validate state-changing requests
app.add_middleware(CSRFMiddleware)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORSMiddleware must be added last so it becomes the outermost middleware layer,
# ensuring CORS headers are always present on every response (including errors).
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r'^https://[a-zA-Z0-9-]+\.railway\.(app|com)$',  # Allow Railway subdomains for migration flexibility
    allow_credentials=True,
    # Only allow necessary HTTP methods
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    # Only allow necessary headers - added X-CSRF-Token for CSRF protection
    allow_headers=["Authorization", "Content-Type", "Accept", "X-CSRF-Token"],
    # Expose Retry-After and X-CSRF-Token headers for client use
    expose_headers=["Retry-After", "X-Request-ID", "X-CSRF-Token"],
)


# Request size limit middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """
    Middleware to limit request body size.

    Prevents DoS attacks via oversized payloads.
    Returns 413 Payload Too Large if request exceeds limits.

    Handles BOTH:
    - Requests with Content-Length header (checked upfront)
    - Chunked/streaming requests without Content-Length (checked during body read)
    """
    from fastapi.responses import JSONResponse

    content_length = request.headers.get("content-length")

    # Fast-path: reject based on Content-Length header if present
    if content_length:
        try:
            size = int(content_length)
            if size > MAX_REQUEST_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": f"Request payload too large. Maximum size is {MAX_REQUEST_SIZE // (1024*1024)}MB"
                    }
                )
        except (ValueError, TypeError):
            pass

    # For requests WITHOUT Content-Length (chunked transfer),
    # wrap the receive callable to count bytes as they stream in
    received_bytes = 0

    original_receive = request._receive

    async def counting_receive():
        nonlocal received_bytes
        message = await original_receive()
        if message.get("type") == "http.request":
            body = message.get("body", b"")
            received_bytes += len(body)
            if received_bytes > MAX_REQUEST_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"Request payload too large. Maximum size is {MAX_REQUEST_SIZE // (1024*1024)}MB"
                )
        return message

    request._receive = counting_receive

    return await call_next(request)


# Response size limit middleware
@app.middleware("http")
async def limit_response_size(request: Request, call_next):
    """
    Middleware to limit response body size.

    Prevents DoS attacks via oversized responses and protects against
    malicious admins creating scenarios that return very large responses
    (e.g., requesting all delivery logs for a mass notification).

    Returns 500 Internal Server Error if response exceeds limits.

    Handles:
    - Regular responses (checked after generation)
    - Streaming responses (checked during streaming)
    """
    from fastapi.responses import JSONResponse, StreamingResponse

    MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5MB max response body size

    response = await call_next(request)

    # For regular responses, check Content-Length if available
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            size = int(content_length)
            if size > MAX_RESPONSE_SIZE:
                logger.warning(
                    f"Response size {size} bytes exceeds limit {MAX_RESPONSE_SIZE} bytes "
                    f"for {request.method} {request.url.path}"
                )
                return JSONResponse(
                    status_code=500,
                    content={
                        "detail": "Response too large. Please use pagination or filters to reduce the response size."
                    }
                )
        except (ValueError, TypeError):
            pass

    # For streaming responses, wrap the body iterator to count bytes
    if isinstance(response, StreamingResponse):
        original_body = response.body_iterator
        sent_bytes = 0

        async def counting_iterator():
            nonlocal sent_bytes
            async for chunk in original_body:
                sent_bytes += len(chunk)
                if sent_bytes > MAX_RESPONSE_SIZE:
                    logger.warning(
                        f"Streaming response size {sent_bytes} bytes exceeds limit "
                        f"{MAX_RESPONSE_SIZE} bytes for {request.method} {request.url.path}"
                    )
                    raise HTTPException(
                        status_code=500,
                        detail="Response too large. Please use pagination or filters to reduce the response size."
                    )
                yield chunk

        response.body_iterator = counting_iterator()

    return response

# Security headers — registered HERE (after all @app.middleware decorators) so it
# is the absolute outermost layer in Starlette's LIFO middleware stack.
# The two @app.middleware decorators above (limit_request_size, limit_response_size)
# call app.add_middleware() internally when the module loads; they must be INNER
# to SecurityHeadersMiddleware so their early-return 413/500 responses also receive
# HSTS, X-Content-Type-Options, CSP, etc.  Placing this call last guarantees it.
app.add_middleware(SecurityHeadersMiddleware)

# Add custom request logging middleware (after CORS and other middleware)
# REMOVED - was causing issues


# ─── ROUTES ───────────────────────────────────────────────────────────────────

API_PREFIX = "/api/v1"

app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(users_router, prefix=API_PREFIX)
app.include_router(groups_router, prefix=API_PREFIX)
app.include_router(locations_router, prefix=API_PREFIX)
app.include_router(templates_router, prefix=API_PREFIX)
app.include_router(incidents_router, prefix=API_PREFIX)
app.include_router(notifications_router, prefix=API_PREFIX)
app.include_router(webhooks_router, prefix=API_PREFIX)
app.include_router(dashboard_router, prefix=API_PREFIX)
app.include_router(location_router, prefix=API_PREFIX)
app.include_router(location_audience_router, prefix=API_PREFIX)
app.include_router(docs_router, prefix=API_PREFIX)


# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy"}


@app.get("/", tags=["Root"])
def root():
    return {"status": "ok"}
