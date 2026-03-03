from celery import Celery
from app.config import settings

# Railway public Redis requires SSL - handle both rediss:// and redis://
redis_url = settings.REDIS_URL
broker_url = redis_url
backend_url = redis_url

# Build SSL options if using rediss://
ssl_opts = {}
if redis_url.startswith("rediss://"):
    ssl_opts = {"ssl_cert_reqs": None}

celery_app = Celery(
    "tm_alert",
    broker=broker_url,
    backend=backend_url,
    include=["app.tasks", "app.location_tasks", "app.core.location_cache"]
)

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
    beat_schedule={
        "process-scheduled-notifications": {
            "task": "app.tasks.process_scheduled_notifications",
            "schedule": 60.0,
        },
    },
)
