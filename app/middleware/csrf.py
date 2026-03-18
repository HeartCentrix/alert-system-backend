"""
CSRF protection — Synchronised Token + HttpOnly Cookie pattern.

On every response the middleware ensures a 'csrf_token' cookie is present
(HttpOnly so JS cannot access it via document.cookie) AND echoes the token in
the X-CSRF-Token response header so the frontend can read it from there and
keep it in memory.

On state-changing requests (POST, PUT, PATCH, DELETE) the X-CSRF-Token
request header must match the csrf_token cookie value (which the browser
sends automatically, opaque to JS).

Exempt paths (unauthenticated or non-browser callers):
  /api/v1/auth/login, /api/v1/auth/refresh, /api/v1/auth/mfa/verify-login,
  /api/v1/auth/mfa/recovery-code/verify, /api/v1/auth/forgot-password,
  /api/v1/auth/reset-password, /api/v1/webhooks/*

Security: secrets.compare_digest() prevents timing-based token oracle attacks.
"""
import secrets
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

logger = logging.getLogger(__name__)

CSRF_ENFORCE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

CSRF_EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/auth/mfa/verify-login",
    "/api/v1/auth/mfa/recovery-code/verify",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/reset-password",
    "/api/v1/auth/entra/callback",  # OAuth callback — uses state/PKCE instead of CSRF
    "/api/v1/auth/entra/login",     # Login redirect — GET request, no state change
    "/api/v1/auth/providers",        # Public endpoint — no auth required
    "/api/v1/auth/ldap/login",       # LDAP login — uses token-based auth
}
# Prefixes for paths that don't require CSRF (public endpoints, webhooks, etc.)
CSRF_EXEMPT_PREFIXES = ("/api/v1/webhooks/",)

# Specific path patterns that are exempt (using regex-style matching)
CSRF_EXEMPT_PATH_PATTERNS = (
    # Safety check-in response uses token-based JWT auth (no CSRF token needed)
    # Pattern: /api/v1/notifications/{id}/respond
    lambda path: path.startswith("/api/v1/notifications/") and path.endswith("/respond"),
)

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"
CSRF_TOKEN_BYTES = 32


class CSRFMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next) -> Response:
        existing_token = request.cookies.get(CSRF_COOKIE_NAME)
        csrf_token = existing_token if existing_token else secrets.token_hex(CSRF_TOKEN_BYTES)

        if request.method in CSRF_ENFORCE_METHODS:
            path = request.url.path
            is_exempt = (
                path in CSRF_EXEMPT_PATHS or
                any(path.startswith(p) for p in CSRF_EXEMPT_PREFIXES) or
                any(pattern(path) for pattern in CSRF_EXEMPT_PATH_PATTERNS)
            )
            if not is_exempt:
                header_token = request.headers.get(CSRF_HEADER_NAME, "")
                if not header_token or not existing_token:
                    logger.warning(
                        f"CSRF validation failed — missing token. "
                        f"path={path} method={request.method}"
                    )
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF validation failed. Refresh the page and try again."}
                    )
                if not secrets.compare_digest(header_token, existing_token):
                    logger.warning(f"CSRF token mismatch. path={path} method={request.method}")
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF validation failed. Refresh the page and try again."}
                    )

        response: Response = await call_next(request)

        # Set csrf_token cookie if not present.
        # HttpOnly: JS cannot read it via document.cookie (mitigates XSS theft).
        # The frontend reads the token from the X-CSRF-Token response header
        # and keeps it in memory to send on subsequent state-changing requests.
        # SameSite=None + Secure: required for cross-origin (Vercel → Railway).
        # In development mode, secure=False and samesite=lax so localhost works.
        if not existing_token:
            from app.config import settings
            is_production = settings.APP_ENV != "development"
            # path="/api" scopes the cookie to API endpoints only — avoids ZAP's
            # "Loosely Scoped Cookie" alert that fires for path="/".
            # Secure=True always (modern browsers accept it on localhost).
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=csrf_token,
                httponly=True,
                secure=True,
                samesite="none" if is_production else "lax",
                path="/api",
                max_age=86400,
            )

        # Always send CSRF token in response header so cross-origin frontends
        # can read it (document.cookie only sees same-origin cookies).
        response.headers["X-CSRF-Token"] = csrf_token

        return response
