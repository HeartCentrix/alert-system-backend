"""
Security-related user notifications.
All sends are fire-and-forget — failures are logged but never block auth flow.
"""

import asyncio
import logging
from typing import Set
from app.services.email_service import send_email

logger = logging.getLogger(__name__)

# Keep strong references to background tasks to prevent premature GC
_background_tasks: Set[asyncio.Task] = set()

LOCKOUT_SUBJECT = "Suspicious login activity on your account"

LOCKOUT_BODY = """
Someone attempted to log into your account {attempt_count} times with an incorrect password.

If this was you, you can try again after the temporary lockout expires.

If this was NOT you:
  1. Change your password immediately
  2. Contact your administrator if you suspect unauthorized access

Details:
  - IP Address: {ip_address}
  - Time: {timestamp}

This is an automated security alert. Do not reply to this email.
""".strip()

RECOVERY_CODES_REGENERATED_SUBJECT = "Security Alert: Recovery codes regenerated"

RECOVERY_CODES_REGENERATED_BODY = """
Your MFA recovery codes were regenerated on {timestamp}.

Details:
  - IP Address: {ip_address}
  - Method: {method}
  - Old codes invalidated: {old_codes_count}

If this was you:
  - Store your new recovery codes in a secure location
  - Each code can only be used once
  - Keep them separate from your password manager for security

If this was NOT you:
  1. Log in immediately and regenerate your codes again
  2. Change your password
  3. Contact your administrator

This is an automated security alert. Do not reply to this email.
""".strip()


async def notify_suspicious_login(
    email: str,
    attempt_count: int,
    ip_address: str,
    timestamp: str,
):
    """
    Fire-and-forget email alert for suspicious login activity.
    Runs in background — does NOT block the login response.
    """
    body = LOCKOUT_BODY.format(
        attempt_count=attempt_count,
        ip_address=ip_address,
        timestamp=timestamp,
    )

    # Fire and forget — store reference to prevent premature garbage collection
    task = asyncio.create_task(_safe_send(email, LOCKOUT_SUBJECT, body))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def notify_recovery_codes_regenerated(
    email: str,
    ip_address: str,
    method: str,
    old_codes_count: int,
    timestamp: str,
):
    """
    Fire-and-forget email alert when recovery codes are regenerated.
    Per OWASP recommendation, users should be notified of MFA factor changes.
    Runs in background — does NOT block the regeneration response.
    """
    body = RECOVERY_CODES_REGENERATED_BODY.format(
        ip_address=ip_address,
        method=method,
        old_codes_count=old_codes_count,
        timestamp=timestamp,
    )

    # Fire and forget — store reference to prevent premature garbage collection
    task = asyncio.create_task(_safe_send(email, RECOVERY_CODES_REGENERATED_SUBJECT, body))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def _safe_send(to: str, subject: str, body: str):
    """Wrapper that catches all exceptions to prevent task crashes."""
    try:
        await send_email(to, subject, body)
    except Exception as e:
        logger.error(f"Security notification failed for {to}: {e}")
