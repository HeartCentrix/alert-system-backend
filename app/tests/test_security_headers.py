"""
Security Headers Tests

Tests to verify that OWASP-recommended HTTP security headers
are present on all API responses.

This addresses CWE-693: Protection Mechanism Failure
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

REQUIRED_HEADERS = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "referrer-policy": "strict-origin-when-cross-origin",
    "content-security-policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net"
    ),
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "cache-control": "no-store",
}


@pytest.mark.asyncio
async def test_security_headers_present():
    """Every response must include all OWASP security headers."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    for header, expected_value in REQUIRED_HEADERS.items():
        assert header in response.headers, f"Missing header: {header}"
        assert response.headers[header] == expected_value, (
            f"{header}: expected '{expected_value}', "
            f"got '{response.headers[header]}'"
        )


@pytest.mark.asyncio
async def test_security_headers_on_error_responses():
    """Headers must be present even on 404/500 responses."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/nonexistent-route-12345")

    for header in REQUIRED_HEADERS:
        assert header in response.headers, (
            f"Missing header on error response: {header}"
        )


@pytest.mark.asyncio
async def test_security_headers_on_health_endpoint():
    """Security headers must be present on health check endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    for header in REQUIRED_HEADERS:
        assert header in response.headers, (
            f"Missing header on health endpoint: {header}"
        )


@pytest.mark.asyncio
async def test_pragma_header_present():
    """Pragma: no-cache header must be present for HTTP/1.0 compatibility."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert "pragma" in response.headers, "Missing Pragma header"
    assert response.headers["pragma"] == "no-cache"
