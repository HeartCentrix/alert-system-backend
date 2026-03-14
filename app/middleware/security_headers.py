from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse


# Attack patterns checked on every incoming request.
# These are injected into query strings, form params, and path segments
# by ZAP's active scanner and real attackers.
_ATTACK_CHECKS = [
    # Spring4Shell / Java classloader probe (CVE-2022-22965)
    ("class.module.classloader",   "class%2emodule%2eclassloader"),
    # HTTP response splitting — raw or URL-encoded CR/LF
    ("%0d", "%0a"),
    # Server-side template injection (Velocity, Freemarker, Jinja2…)
    ("#set(", "%23set(", "${", "%24{"),
    # Format-string injection patterns
    ("%n%s",),
]


def _has_attack_pattern(raw: str) -> bool:
    lower = raw.lower()
    for group in _ATTACK_CHECKS:
        if any(p in lower for p in group):
            return True
    # Windows printf format specifiers (%1!s!, %2!s!, …)
    import re
    if re.search(r"%[0-9]+![sdn]!", lower):
        return True
    return False


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects OWASP-recommended HTTP security headers into every response.
    Registered as the outermost middleware so no response escapes unprotected.
    Also blocks common attack probes in request URLs before they reach the app.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # ── Request-level attack detection ───────────────────────────────────
        # Check the full raw URL (path + query string) for known attack patterns.
        # This must run BEFORE call_next so malicious parameters never reach
        # route handlers or database queries.
        raw_url = str(request.url)
        if _has_attack_pattern(raw_url):
            resp = PlainTextResponse("Bad Request", status_code=400)
            self._apply_headers(resp)
            return resp

        response: Response = await call_next(request)
        self._apply_headers(response)
        return response

    @staticmethod
    def _apply_headers(response: Response) -> None:
        """Add all OWASP security headers to a response object."""
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com"
        )
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-DNS-Prefetch-Control"] = "off"
