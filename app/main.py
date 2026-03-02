from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import User, UserRole, AlertChannel
from app.core.security import hash_password
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def ensure_alertchannel_enum():
    """Ensure 'web' value exists in alertchannel enum (PostgreSQL)."""
    db = SessionLocal()
    try:
        result = db.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_enum WHERE enumlabel = 'web' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'alertchannel'))"
        ).scalar()
        
        if not result:
            db.execute("ALTER TYPE alertchannel ADD VALUE IF NOT EXISTS 'web'")
            db.commit()
            logger.info("Added 'web' to alertchannel enum")
        else:
            logger.info("alertchannel enum already has 'web' value")
    except Exception as e:
        logger.error(f"Error ensuring alertchannel enum: {e}")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all DB tables on startup
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ready")

    # Ensure alertchannel enum has 'web' value
    logger.info("Ensuring alertchannel enum has 'web' value...")
    ensure_alertchannel_enum()

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
    logger.info("Shutting down TM Alert")


app = FastAPI(
    title="TM Alert API",
    description="Emergency Notification System for Taylor Morrison",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL, "http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
