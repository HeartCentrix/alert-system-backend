"""
Centralized logging configuration for TM Alert.

Solves the uvicorn logging override problem:
- uvicorn calls dictConfig() on startup, which REPLACES any handlers
  set by logging.basicConfig() in main.py
- This module uses dictConfig() too, and is called AFTER uvicorn's
  initialization (inside the lifespan context), so it wins

Also suppresses noisy third-party loggers that leak credentials:
- httpx: logs full URLs with API keys in query params
- twilio: logs Account SIDs in API paths
- boto3/botocore: logs AWS credential-adjacent info
"""

import logging
import logging.config


LOGGING_CONFIG = {
    "version": 1,
    # CRITICAL: This must be False. Setting True would disable all loggers
    # created before this config runs (which is all of them, since modules
    # create loggers at import time with logging.getLogger(__name__))
    "disable_existing_loggers": False,
    "filters": {
        # This filter injects request_id into EVERY log record.
        # Attached to the HANDLER (not logger) so every single log record
        # gets request_id injected, regardless of which logger emitted it.
        # Without this, %(request_id)s in the format string causes:
        # ValueError: Formatting field not found in record: 'request_id'
        "request_id": {
            "()": "app.middleware.request_id.RequestIDLogFilter",
        },
    },
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "stream": "ext://sys.stdout",
            # KEY FIX: filter is on the HANDLER, not on individual loggers
            # This means EVERY log record that reaches this handler gets
            # request_id injected, regardless of which logger created it
            "filters": ["request_id"],
        },
    },
    "loggers": {
        # ─── Root logger: catches everything ─────────────────────
        "": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        # ─── Uvicorn loggers ─────────────────────────────────────
        # Use OUR formatter instead of uvicorn's default
        "uvicorn": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "uvicorn.error": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        # Enable access logs - shows every HTTP request
        "uvicorn.access": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        # ─── Noisy/leaky third-party loggers ─────────────────────
        # httpx: logs full URLs with API keys in query params
        "httpx": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        "httpcore": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        # Twilio: logs Account SID and full API URLs
        "twilio.http_client": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        # AWS SDK: logs credential-adjacent info
        "botocore": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        "boto3": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        "urllib3": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        # SQLAlchemy: extremely verbose at INFO (logs every SQL query)
        "sqlalchemy.engine": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
    },
}


def setup_logging() -> None:
    """
    Apply the logging configuration.

    Call this inside the FastAPI lifespan context (after uvicorn has
    already applied its own dictConfig). This ensures our config
    overwrites uvicorn's, not the other way around.
    """
    logging.config.dictConfig(LOGGING_CONFIG)
