from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects OWASP-recommended HTTP security headers into every response.
    Registered as the outermost middleware so no response escapes unprotected.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # Clickjacking protection — block all iframe embedding
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME-type sniffing on uploaded/served content
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Force HTTPS for 1 year, including subdomains
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Control referrer leakage — send origin only on cross-origin
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # CSP — allow same-origin plus CDN resources for Swagger/OpenAPI docs
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net"
        )

        # Disable browser features the API does not use
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Prevent caching of authenticated responses
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

        # Prevent speculative DNS resolution of hostnames in response bodies
        response.headers["X-DNS-Prefetch-Control"] = "off"

        return response
