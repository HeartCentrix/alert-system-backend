"""
Email notification service.
Uses SMTP for async email delivery.
All failures are logged but never raise — email failures must not break the login flow.
"""

import logging
from email.message import EmailMessage
import aiosmtplib
from app.config import settings

logger = logging.getLogger(__name__)


async def send_email(to: str, subject: str, body: str) -> bool:
    """
    Send an email via SMTP. Returns True on success, False on failure.
    Never raises — email failures must not break the login flow.
    """
    try:
        if not settings.SMTP_HOST or not settings.SMTP_USER:
            logger.warning(f"[MOCK EMAIL] To: {to} | Subject: {subject}")
            return True

        message = EmailMessage()
        message["From"] = settings.EMAIL_FROM
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)

        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            use_tls=True,
        )
        logger.info(f"Email sent to {to}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}")
        return False
