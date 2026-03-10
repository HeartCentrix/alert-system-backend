"""
Redis-backed rate limiting for login attempts and notification dispatch.

Stores two counter types:
  - Account-level: tracks per-user failed attempts (keyed by user ID)
  - IP-level: tracks per-IP failed attempts (keyed by IP address)
  - Notification-level: tracks notification dispatch rate per user

All keys have TTL auto-expiry so counters self-clean.

Security: Redis connections use TLS with full certificate verification
when using rediss:// scheme (ssl_cert_reqs=CERT_REQUIRED).
"""

import redis.asyncio as redis
import ssl
from datetime import timedelta
from app.config import settings

# Build SSL options for TLS connections
# SECURITY: Require TLS with full certificate verification (CERT_REQUIRED)
# Self-signed or unverified certificates are NOT accepted
ssl_opts = {}
if settings.REDIS_URL.startswith("rediss://"):
    ssl_opts = {
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_check_hostname": True,
    }

# Connection pool — shared across the application
_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=20,
    decode_responses=True,
    **ssl_opts,
)


def _get_client() -> redis.Redis:
    return redis.Redis(connection_pool=_pool)


# ──────────────────────────────────────────────
# Key schema
# ──────────────────────────────────────────────
def _account_key(user_id: int) -> str:
    return f"login:fail:account:{user_id}"


def _account_lock_key(user_id: int) -> str:
    return f"login:lock:account:{user_id}"


def _ip_key(ip: str) -> str:
    return f"login:fail:ip:{ip}"


def _ip_lock_key(ip: str) -> str:
    return f"login:lock:ip:{ip}"


def _device_key(fingerprint: str) -> str:
    return f"login:fail:device:{fingerprint}"


def _notification_key(user_id: int) -> str:
    """Key for notification dispatch rate limiting."""
    return f"notification:dispatch:user:{user_id}"


# ──────────────────────────────────────────────
# Account-level operations
# ──────────────────────────────────────────────
async def record_failed_login(user_id: int) -> int:
    """
    Increment failed login counter for a user account.
    Returns the new attempt count.
    Sets a 24-hour TTL window — counter resets if no failures for 24h.
    """
    r = _get_client()
    key = _account_key(user_id)

    count = await r.incr(key)
    if count == 1:
        await r.expire(key, timedelta(hours=24))

    # Apply lockout if threshold reached
    await _apply_account_lockout(r, user_id, count)

    return count


async def _apply_account_lockout(r: redis.Redis, user_id: int, count: int):
    """Apply tiered lockout duration based on failure count."""
    if count < 5:
        return

    if count < 10:
        lockout = timedelta(minutes=1)
    elif count < 15:
        lockout = timedelta(minutes=5)
    elif count < 20:
        lockout = timedelta(minutes=15)
    elif count < 30:
        lockout = timedelta(hours=1)
    else:
        lockout = timedelta(hours=24)  # Effectively disabled

    await r.set(_account_lock_key(user_id), "locked", ex=lockout)


async def is_account_locked(user_id: int) -> bool:
    """Check if account is currently in lockout period."""
    r = _get_client()
    return await r.exists(_account_lock_key(user_id)) == 1


async def get_account_failure_count(user_id: int) -> int:
    """Get current failure count for a user. Returns 0 if no failures."""
    r = _get_client()
    count = await r.get(_account_key(user_id))
    return int(count) if count else 0


async def clear_account_failures(user_id: int):
    """Reset on successful login — clears both counter and lock."""
    r = _get_client()
    await r.delete(_account_key(user_id), _account_lock_key(user_id))


# ──────────────────────────────────────────────
# IP-level operations
# ──────────────────────────────────────────────
async def record_ip_failure(ip: str) -> int:
    """
    Increment failed login counter for an IP address.
    Returns the new attempt count.
    """
    r = _get_client()
    key = _ip_key(ip)

    count = await r.incr(key)
    if count == 1:
        await r.expire(key, timedelta(hours=24))

    await _apply_ip_lockout(r, ip, count)

    return count


async def _apply_ip_lockout(r: redis.Redis, ip: str, count: int):
    """Progressive IP lockout tiers."""
    if count < 10:
        return
    elif count < 20:
        lockout = timedelta(minutes=5)
    elif count < 50:
        lockout = timedelta(minutes=30)
    else:
        lockout = timedelta(hours=24)

    await r.set(_ip_lock_key(ip), "locked", ex=lockout)


async def is_ip_locked(ip: str) -> bool:
    """Check if IP is currently blocked."""
    r = _get_client()
    return await r.exists(_ip_lock_key(ip)) == 1


async def get_ip_failure_count(ip: str) -> int:
    """Get current failure count for an IP."""
    r = _get_client()
    count = await r.get(_ip_key(ip))
    return int(count) if count else 0


# ──────────────────────────────────────────────
# Device fingerprint operations
# ──────────────────────────────────────────────
async def record_device_failure(fingerprint: str) -> int:
    """Track failures per device fingerprint."""
    r = _get_client()
    key = _device_key(fingerprint)

    count = await r.incr(key)
    if count == 1:
        await r.expire(key, timedelta(hours=24))

    return count


async def get_device_failure_count(fingerprint: str) -> int:
    """Get failure count for a device fingerprint."""
    r = _get_client()
    count = await r.get(_device_key(fingerprint))
    return int(count) if count else 0


# ──────────────────────────────────────────────
# Notification dispatch rate limiting
# ──────────────────────────────────────────────
# Constants
NOTIFICATION_RATE_LIMIT_MAX = 10  # Max notifications per minute
NOTIFICATION_RATE_LIMIT_WINDOW = 60  # 60 seconds window


async def check_notification_rate_limit(user_id: int) -> tuple[bool, int]:
    """
    Check if user has exceeded notification dispatch rate limit.

    Args:
        user_id: ID of the user creating the notification

    Returns:
        Tuple of (is_allowed, retry_after_seconds)
        - is_allowed: True if user can send notification
        - retry_after_seconds: Seconds until rate limit resets (0 if allowed)
    """
    r = _get_client()
    key = _notification_key(user_id)

    count = await r.get(key)
    if count is None:
        return True, 0

    count = int(count)
    if count >= NOTIFICATION_RATE_LIMIT_MAX:
        # Get TTL for retry-after header
        ttl = await r.ttl(key)
        return False, ttl if ttl > 0 else NOTIFICATION_RATE_LIMIT_WINDOW

    return True, 0


async def record_notification_dispatch(user_id: int) -> int:
    """
    Record a notification dispatch for rate limiting.

    Args:
        user_id: ID of the user creating the notification

    Returns:
        The new dispatch count within the current window
    """
    r = _get_client()
    key = _notification_key(user_id)

    count = await r.incr(key)
    if count == 1:
        # First dispatch in window, set TTL
        await r.expire(key, timedelta(seconds=NOTIFICATION_RATE_LIMIT_WINDOW))

    return count


async def get_notification_dispatch_count(user_id: int) -> int:
    """Get current notification dispatch count for a user."""
    r = _get_client()
    key = _notification_key(user_id)
    count = await r.get(key)
    return int(count) if count else 0


async def clear_notification_limit(user_id: int):
    """Clear notification rate limit for a user (admin use only)."""
    r = _get_client()
    key = _notification_key(user_id)
    await r.delete(key)
