from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import logging

from sqlalchemy import text
from app.config import settings
from app.middleware.security_headers import SecurityHeadersMiddleware
from sqlalchemy import text
from app.database import engine, Base, SessionLocal, ensure_column_exists
from app.models import (
    User, UserRole, AlertChannel, Location, Group, NotificationTemplate,
    Incident, Notification, DeliveryLog, NotificationResponse, IncomingMessage,
    AuditLog, RefreshToken, LoginAttempt, UserLocation, UserLocationHistory
)
from app.core.security import hash_password
from app.core.location_cache import init_location_cache, close_location_cache
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Redis cache for location autocomplete
    logger.info("Initializing location cache...")
    try:
        await init_location_cache(settings.REDIS_URL)
        logger.info("Location cache initialized")
    except Exception as e:
        logger.error(f"Failed to initialize location cache: {e}")
    
    # Create all DB tables on startup
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ready")

    # Ensure alertchannel enum has 'web' value
    logger.info("Ensuring alertchannel enum has 'web' value...")
    ensure_alertchannel_enum()

    # Ensure User table has latitude/longitude columns
    _ensure_user_location_columns()

    # Ensure audit_logs table has user_email column
    logger.info("Ensuring audit_logs table has user_email column...")
    _ensure_audit_log_user_email()

    # Seed default super admin if no users exist
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                email="admin@tmalert.com",
                hashed_password=hash_password("Admin@123456"),
                first_name="Super",
                last_name="Admin",
                role=UserRole.SUPER_ADMIN,
                is_active=True
            )
            db.add(admin)
            db.commit()
            logger.info("Default admin created: admin@tmalert.com / Admin@123456")
    finally:
        db.close()

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

logger.info(f"CORS allowed origins: {allowed_origins}")

# Security headers — MUST be registered first (outermost layer)
# Wraps all other middleware to ensure headers on every response
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    # Only allow necessary HTTP methods
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    # Only allow necessary headers
    allow_headers=["Authorization", "Content-Type", "Accept"],
    # Expose Retry-After header for rate limiting countdown timer
    expose_headers=["Retry-After"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

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
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "env": settings.APP_ENV,
        "version": "1.0.0"
    }


@app.get("/", tags=["Root"])
def root():
    return {
        "message": "TM Alert API",
        "docs": "/api/docs",
        "version": "1.0.0"
    }
