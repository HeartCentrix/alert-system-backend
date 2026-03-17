"""
Request ID middleware for per-request correlation.

Generates a UUID4 for each incoming request and makes it available:
1. As a response header: X-Request-ID
2. In all log messages via a custom logging filter
3. To any code via get_request_id() (reads from ContextVar)

Accepts client-provided X-Request-ID if present and valid,
enabling end-to-end tracing across frontend → API → services.
"""

import uuid
import re
import logging
from contextvars import ContextVar
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ContextVar holds the request ID for the current async context.
# Automatically scoped per-request in async frameworks — no cleanup needed.
# Default "" so log filter never crashes if accessed outside a request.
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")

# Strict validation: only allow UUID-shaped strings (hex + hyphens, 36 chars max)
# Prevents log injection via crafted X-Request-ID headers containing newlines,
# ANSI escape codes, or other control characters.
_VALID_REQUEST_ID = re.compile(r"^[a-fA-F0-9\-]{1,36}$")


def get_request_id() -> str:
    """Get the current request's correlation ID.
    
    Call this from anywhere — endpoints, services, utilities.
    Returns "" if called outside a request context (e.g., startup, Celery tasks).
    """
    return request_id_ctx.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Assigns a unique ID to each request for log correlation.
    
    - Checks for client-provided X-Request-ID header first
    - Falls back to generating a new UUID4
    - Stores in ContextVar for log filter access
    - Adds X-Request-ID to response headers
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Accept client-provided ID if it's a valid UUID format
        client_id = request.headers.get("x-request-id", "")
        if client_id and _VALID_REQUEST_ID.match(client_id):
            rid = client_id
        else:
            rid = str(uuid.uuid4())

        # Store in ContextVar — all code in this request's async chain can read it
        token = request_id_ctx.set(rid)

        try:
            response: Response = await call_next(request)
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            # Reset ContextVar to prevent leaking between requests
            # (defensive — contextvars auto-scope in asyncio tasks,
            # but explicit reset is best practice)
            request_id_ctx.reset(token)


class RequestIDLogFilter(logging.Filter):
    """
    Logging filter that injects request_id into every log record.
    
    Attach to the root logger so ALL loggers (app.api.auth, app.services.messaging,
    uvicorn, etc.) automatically get the request ID without any code changes.
    
    Usage in log format: %(request_id)s
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        return True
