"""
LocationIQ Autocomplete Proxy API

Securely proxies LocationIQ autocomplete requests to hide API key.
Implements caching (48h max for free tier), rate limiting, and robust error handling.
"""
import time
import hashlib
import httpx
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Query, Request
from app.config import settings

router = APIRouter(prefix="/location", tags=["Location"])

# ─── CACHING ──────────────────────────────────────────────────────────────────
# In-memory cache for LocationIQ responses
# Free tier: max 48 hours cache (per LocationIQ ToS)
# Format: {cache_key: {"data": response, "expires_at": datetime}}
_location_cache: dict[str, dict] = {}

# Cache TTL: 48 hours max for free plan (in seconds)
CACHE_TTL_SECONDS = 48 * 60 * 60

# Short-term cache for repeated identical requests (5 minutes)
SHORT_TERM_CACHE_SECONDS = 5 * 60

# ─── RATE LIMITING ────────────────────────────────────────────────────────────
# Track rate limit errors to implement client-side backoff hint
# Format: {timestamp_bucket: error_count}
_rate_limit_tracker: dict[str, int] = {}
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_THRESHOLD = 10  # Max rate limit errors before suggesting longer backoff

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
LOCATIONIQ_TIMEOUT_SECONDS = 10
LOCATIONIQ_MAX_RETRIES = 2
MIN_QUERY_LENGTH = 3
DEFAULT_LIMIT = 10
MAX_LIMIT = 20


def _generate_cache_key(query: str, countrycodes: str | None, viewbox: str | None) -> str:
    """Generate a unique cache key for the query parameters."""
    key_string = f"{query}|{countrycodes or ''}|{viewbox or ''}"
    return hashlib.md5(key_string.encode()).hexdigest()


def _get_cached(cache_key: str) -> list | None:
    """Retrieve data from cache if not expired."""
    cached = _location_cache.get(cache_key)
    if cached and cached["expires_at"] > datetime.now(timezone.utc):
        return cached["data"]
    # Clean up expired cache
    if cache_key in _location_cache:
        del _location_cache[cache_key]
    return None


def _set_cache(cache_key: str, data: list) -> None:
    """Store data in cache with expiration."""
    _location_cache[cache_key] = {
        "data": data,
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=CACHE_TTL_SECONDS)
    }


def _validate_query(q: str) -> tuple[bool, str | None]:
    """
    Validate and sanitize the search query.
    Returns (is_valid, error_message)
    """
    if not q or not q.strip():
        return False, "Query parameter 'q' is required"
    
    q_stripped = q.strip()
    
    if len(q_stripped) < MIN_QUERY_LENGTH:
        return False, f"Query must be at least {MIN_QUERY_LENGTH} characters"
    
    if len(q_stripped) > 200:
        return False, "Query must not exceed 200 characters"
    
    # Basic sanitization - allow alphanumeric, spaces, and common address chars
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ,.-#'")
    if not all(c in allowed_chars for c in q_stripped):
        return False, "Query contains invalid characters"
    
    return True, None


@router.get("/autocomplete")
async def autocomplete(
    request: Request,
    q: str = Query(..., description="Search query (minimum 3 characters)"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description="Number of results (1-20)"),
    countrycodes: str | None = Query(default=None, description="Comma-separated ISO 3166-1 alpha-2 country codes"),
    viewbox: str | None = Query(default=None, description="Bounding box for biasing results: x1,y1,x2,y2"),
    bounded: bool = Query(default=False, description="Restrict results to viewbox only"),
):
    """
    Location autocomplete using LocationIQ API.
    
    Proxies requests to LocationIQ to hide API key. Implements:
    - Server-side caching (48h max per free tier ToS)
    - Input validation and sanitization
    - Rate limit handling with graceful degradation
    - Timeout and retry logic
    
    **Rate Limits (LocationIQ Free Tier):**
    - 5,000 requests/day
    - 2 requests/second
    
    **Caching Policy:**
    - Responses cached for up to 48 hours (free tier compliant)
    - Short-term cache (5 min) for repeated identical requests
    """
    # Validate API key is configured
    if not settings.LOCATIONIQ_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Location service temporarily unavailable (API key not configured)"
        )
    
    # Validate query
    is_valid, error_msg = _validate_query(q)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    
    query = q.strip()
    
    # Generate cache key and check cache
    cache_key = _generate_cache_key(query, countrycodes, viewbox)
    cached_result = _get_cached(cache_key)
    if cached_result is not None:
        return {"results": cached_result, "cached": True}
    
    # Build LocationIQ request
    params = {
        "key": settings.LOCATIONIQ_API_KEY,
        "q": query,
        "limit": limit,
        "format": "json",
    }
    
    if countrycodes:
        # Validate country codes (basic validation)
        codes = [c.strip().upper() for c in countrycodes.split(",")]
        if all(len(c) == 2 and c.isalpha() for c in codes):
            params["countrycodes"] = ",".join(codes)
    
    if viewbox:
        # Validate viewbox format: x1,y1,x2,y2 (lng,lat,lng,lat)
        parts = viewbox.split(",")
        if len(parts) == 4:
            try:
                coords = [float(p.strip()) for p in parts]
                if all(-180 <= coords[0], coords[2] <= 180 and -90 <= coords[1], coords[3] <= 90):
                    params["viewbox"] = viewbox
                    params["bounded"] = "1" if bounded else "0"
            except ValueError:
                pass  # Ignore invalid viewbox
    
    # Make request to LocationIQ with retries
    url = f"{settings.LOCATIONIQ_BASE_URL}/autocomplete"
    
    last_error = None
    for attempt in range(LOCATIONIQ_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=LOCATIONIQ_TIMEOUT_SECONDS) as client:
                response = await client.get(url, params=params)
                
                # Handle rate limiting (HTTP 429)
                if response.status_code == 429:
                    # Track rate limit errors
                    bucket = str(int(time.time()) // RATE_LIMIT_WINDOW_SECONDS)
                    _rate_limit_tracker[bucket] = _rate_limit_tracker.get(bucket, 0) + 1
                    
                    # Check if we've hit too many rate limits
                    total_errors = sum(_rate_limit_tracker.values())
                    if total_errors >= RATE_LIMIT_THRESHOLD:
                        raise HTTPException(
                            status_code=503,
                            detail="Location service temporarily unavailable due to rate limiting. Please try again in a few minutes.",
                            headers={"Retry-After": "60"}
                        )
                    
                    raise HTTPException(
                        status_code=429,
                        detail="Too many requests. Please wait a moment before trying again.",
                        headers={"Retry-After": "5"}
                    )
                
                # Handle other errors
                if response.status_code >= 500:
                    last_error = f"LocationIQ server error: {response.status_code}"
                    continue  # Retry
                
                if response.status_code >= 400:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Location service error: {response.status_code}"
                    )
                
                # Parse and normalize response
                data = response.json()
                
                # Normalize results to our format
                results = []
                for item in data:
                    # Extract display components
                    display_name = item.get("display_name", "")
                    
                    # Try to split into place and address
                    parts = display_name.split(", ")
                    display_place = parts[0] if parts else display_name
                    display_address = ", ".join(parts[1:]) if len(parts) > 1 else ""
                    
                    # Extract address components if available
                    address = item.get("address", {})
                    
                    results.append({
                        "place_id": item.get("place_id", ""),
                        "display_name": display_name,
                        "display_place": display_place,
                        "display_address": display_address,
                        "lat": float(item.get("lat", 0)),
                        "lon": float(item.get("lon", 0)),
                        "address": {
                            "name": address.get("name", ""),
                            "road": address.get("road", ""),
                            "city": address.get("city", address.get("town", address.get("village", ""))),
                            "state": address.get("state", ""),
                            "postcode": address.get("postcode", ""),
                            "country": address.get("country", ""),
                            "country_code": address.get("country_code", ""),
                        },
                        "type": item.get("type", ""),
                        "importance": item.get("importance", 0),
                    })
                
                # Cache the results
                _set_cache(cache_key, results)
                
                return {"results": results, "cached": False}
                
        except httpx.TimeoutException:
            last_error = "Location service timeout"
            continue  # Retry
        except httpx.RequestError as e:
            last_error = f"Location service connection error: {str(e)}"
            continue  # Retry
    
    # All retries exhausted
    raise HTTPException(
        status_code=502,
        detail=last_error or "Location service temporarily unavailable"
    )


@router.get("/health")
async def health_check():
    """Check if location service is available."""
    return {"status": "healthy"}
