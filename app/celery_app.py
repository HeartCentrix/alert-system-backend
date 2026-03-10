from celery import Celery
from celery.schedules import crontab
from app.config import settings
import ssl

# Railway public Redis requires SSL - handle both rediss:// and redis://
redis_url = settings.REDIS_URL
broker_url = redis_url
backend_url = redis_url

# Build SSL options if using rediss://
# SECURITY: Require TLS with full certificate verification (CERT_REQUIRED)
# Self-signed or unverified certificates are NOT accepted
ssl_opts = {}
if redis_url.startswith("rediss://"):
    ssl_opts = {
        "ssl_cert_reqs": ssl.CERT_REQUIRED,  # Enforce certificate verification
        "ssl_check_hostname": True,  # Verify hostname matches certificate
    }

celery_app = Celery(
    "tm_alert",
    broker=broker_url,
    backend=backend_url,
    include=["app.tasks", "app.location_tasks", "app.core.location_cache"]
)

# Use Redis as the beat scheduler backend to avoid file permission issues
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="America/New_York",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_use_ssl=ssl_opts if ssl_opts else None,
    redis_backend_use_ssl=ssl_opts if ssl_opts else None,
    beat_scheduler="celery.beat:PersistentScheduler",  # Use persistent scheduler
    beat_schedule_filename="/tmp/celerybeat-schedule",  # Use /tmp to avoid permission issues
    beat_schedule={
        "process-scheduled-notifications": {
            "task": "app.tasks.process_scheduled_notifications",
            "schedule": 60.0,
        },
        "periodic-geofence-check": {
            "task": "app.location_tasks.periodic_geofence_check",
            "schedule": 300.0,  # Every 5 minutes
        },
        "cleanup-expired-assignments": {
            "task": "app.location_tasks.cleanup_expired_assignments",
            "schedule": 86400.0,  # Daily
        },
        "refresh-redis-geo-index": {
            "task": "app.location_tasks.refresh_redis_geo_index",
            "schedule": 3600.0,  # Hourly
        },
    },
)
