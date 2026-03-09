import logging
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)


# ─── TWILIO SERVICE ───────────────────────────────────────────────────────────

class TwilioService:
    def __init__(self):
        self.client = None
        self._init_client()

    def _init_client(self):
        if settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN:
            try:
                from twilio.rest import Client
                self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                logger.info("Twilio client initialized")
            except Exception as e:
                logger.warning(f"Twilio init failed: {e}")

    def send_sms(self, to: str, body: str) -> dict:
        if not self.client:
            logger.warning(f"[MOCK SMS] To: {to} | Body: {body[:50]}...")
            return {"sid": "MOCK_SID", "status": "sent", "mock": True}
        try:
            message = self.client.messages.create(
                body=body,
                from_=settings.TWILIO_FROM_NUMBER,
                to=to
            )
            return {"sid": message.sid, "status": message.status}
        except Exception as e:
            logger.error(f"SMS failed to {to}: {e}")
            return {"error": str(e), "status": "failed"}

    def make_voice_call(self, to: str, message: str) -> dict:
        """Make a voice call with TwiML for keypress response.
        
        Uses /voice/response endpoint for Gather action and /voice/status for callbacks.
        """
        if not self.client:
            logger.warning(f"[MOCK VOICE] To: {to} | Message: {message[:50]}...")
            return {"sid": "MOCK_VOICE_SID", "status": "initiated", "mock": True}
        try:
            # Use full absolute URL for the Gather action (Twilio requirement)
            # IMPORTANT: Must match the route in webhooks.py: @router.post("/voice/response")
            voice_webhook_url = f"{settings.BACKEND_URL}/api/v1/webhooks/voice/response"
            status_callback_url = f"{settings.BACKEND_URL}/api/v1/webhooks/voice/status"
            
            # Validate URL format to prevent callback failures
            if not voice_webhook_url.startswith("http"):
                logger.error(f"Invalid voice webhook URL: {voice_webhook_url}")
                raise ValueError("BACKEND_URL must be a valid HTTP/HTTPS URL")
            
            # Escape message to prevent XSS in TwiML
            safe_message = _escape_xml(message)
            twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice" loop="2">{safe_message}</Say>
  <Pause length="1"/>
  <Say voice="alice">Press 1 if you are safe. Press 2 if you need help.</Say>
  <Gather numDigits="1" action="{voice_webhook_url}" method="POST">
    <Say>Please press a key now.</Say>
  </Gather>
</Response>"""
            call = self.client.calls.create(
                twiml=twiml,
                from_=settings.TWILIO_FROM_NUMBER,
                to=to,
                status_callback=status_callback_url,
                status_callback_method="POST"
            )
            return {"sid": call.sid, "status": call.status}
        except Exception as e:
            logger.error(f"Voice call failed to {to}: {e}")
            return {"error": str(e), "status": "failed"}

    def send_whatsapp(self, to: str, body: str) -> dict:
        """WhatsApp sending has been removed."""
        logger.warning(f"WhatsApp sending is disabled. To: {to} | Body: {body[:50]}...")
        return {"error": "WhatsApp is disabled", "status": "failed"}


# ─── EMAIL SERVICE (AWS SES) ──────────────────────────────────────────────────

class EmailService:
    def __init__(self):
        self.client = None
        self._init_client()

    def _init_client(self):
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            try:
                import boto3
                self.client = boto3.client(
                    "ses",
                    region_name=settings.AWS_REGION,
                    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
                )
                logger.info("AWS SES client initialized")
            except Exception as e:
                logger.warning(f"SES init failed: {e}")

    def send_email(self, to: str, subject: str, body_text: str, body_html: Optional[str] = None) -> dict:
        if not self.client:
            # MOCK MODE: Print full email content to console for development/testing
            logger.info("=" * 80)
            logger.info("📧 [MOCK EMAIL] Would send to: %s", to)
            logger.info("   Subject: %s", subject)
            logger.info("   --- EMAIL CONTENT ---")
            logger.info("%s", body_text)
            logger.info("   ---------------------")
            logger.info("=" * 80)
            return {"message_id": "MOCK_EMAIL_ID", "status": "sent", "mock": True}
        try:
            html_body = body_html or self._text_to_html(body_text)
            response = self.client.send_email(
                Source=f"{settings.SES_FROM_NAME} <{settings.SES_FROM_EMAIL}>",
                Destination={"ToAddresses": [to]},
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {
                        "Text": {"Data": body_text, "Charset": "UTF-8"},
                        "Html": {"Data": html_body, "Charset": "UTF-8"},
                    },
                },
            )
            return {"message_id": response["MessageId"], "status": "sent"}
        except Exception as e:
            logger.error(f"Email failed to {to}: {e}")
            return {"error": str(e), "status": "failed"}

    def send_password_reset_email(self, to: str, reset_token: str, user_name: str) -> dict:
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        subject = "TM Alert - Password Reset Request"
        # Escape user_name to prevent HTML injection
        safe_user_name = _escape_xml(user_name)
        body_text = f"Hi {user_name},\n\nClick the link to reset your password:\n{reset_url}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, ignore this email."
        body_html = f"""
        <html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e40af; padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">TM Alert</h1>
        </div>
        <div style="padding: 30px;">
            <h2>Password Reset Request</h2>
            <p>Hi {safe_user_name},</p>
            <p>Someone requested a password reset for your TM Alert account.</p>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{reset_url}" style="background: #1e40af; color: white; padding: 12px 24px;
                   text-decoration: none; border-radius: 6px; font-weight: bold;">Reset My Password</a>
            </p>
            <p style="color: #666; font-size: 14px;">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
        </div>
        </body></html>"""
        return self.send_email(to, subject, body_text, body_html)

    def send_welcome_email(self, to: str, user_name: str, password: str) -> dict:
        """Send welcome email with login credentials to newly imported users."""
        login_url = f"{settings.FRONTEND_URL}/#/login"
        subject = "Welcome to TM Alert - Your Login Credentials"
        # Escape user_name to prevent HTML injection
        safe_user_name = _escape_xml(user_name)
        # Escape password to prevent HTML injection (defense in depth)
        safe_password = _escape_xml(password)

        body_text = f"""Hi {user_name},

Welcome to TM Alert! You've been added to the Taylor Morrison emergency notification system.

Your login credentials:
Email: {to}
Temporary Password: {password}

Login here: {login_url}

IMPORTANT SECURITY NOTES:
- Please change your password immediately after logging in
- This is a temporary password - do not share it with anyone
- If you didn't expect this email, contact your administrator

TM Alert sends you critical emergency notifications via SMS, Email, and Voice.

Stay safe,
TM Alert Team
Taylor Morrison"""

        body_html = f"""
        <html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f1f5f9;">
        <div style="background: #1e40af; padding: 25px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 24px;">🚨 TM Alert</h1>
            <p style="color: #93c5fd; margin: 5px 0 0 0; font-size: 14px;">Taylor Morrison Emergency Notification System</p>
        </div>
        <div style="background: white; padding: 30px; margin: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="color: #1e293b; margin-top: 0;">Welcome to TM Alert!</h2>
            <p style="color: #475569;">Hi {safe_user_name},</p>
            <p style="color: #475569;">You've been added to the Taylor Morrison emergency notification system. You'll receive critical emergency alerts via SMS, Email, and Voice.</p>

            <div style="background: #f8fafc; border: 2px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 25px 0;">
                <h3 style="color: #1e40af; margin-top: 0; font-size: 16px;">📧 Your Login Credentials</h3>
                <table style="width: 100%; margin: 15px 0;">
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: 600;">Email:</td>
                        <td style="padding: 8px 0; color: #1e293b; font-family: monospace;">{to}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: 600;">Temporary Password:</td>
                        <td style="padding: 8px 0; font-family: monospace; background: #fef3c7; padding: 4px 8px; border-radius: 4px; color: #92400e;">{safe_password}</td>
                    </tr>
                </table>
                <div style="text-align: center; margin-top: 20px;">
                    <a href="{login_url}" style="background: #1e40af; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Login Now</a>
                </div>
            </div>

            <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; border-radius: 4px;">
                <p style="color: #92400e; margin: 0; font-weight: 600;">⚠️ Important Security Reminders:</p>
                <ul style="color: #92400e; margin: 10px 0 0 0; padding-left: 20px; font-size: 14px;">
                    <li>Change your password immediately after logging in</li>
                    <li>Do not share your password with anyone</li>
                    <li>If you didn't expect this email, contact your administrator</li>
                </ul>
            </div>

            <p style="color: #64748b; font-size: 14px; margin-top: 25px;">Stay safe,<br/><strong>TM Alert Team</strong><br/>Taylor Morrison</p>
        </div>
        <div style="text-align: center; padding: 20px; color: #94a3b8; font-size: 12px;">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>&copy; 2024 Taylor Morrison. All rights reserved.</p>
        </div>
        </body></html>"""

        return self.send_email(to, subject, body_text, body_html)

    def _text_to_html(self, text: str) -> str:
        paragraphs = text.split("\n\n")
        html_parts = [f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paragraphs]
        return f"""<html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e40af; padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">🚨 TM Alert</h1>
        </div>
        <div style="padding: 30px;">{''.join(html_parts)}</div>
        </body></html>"""


# ─── WEBHOOK SERVICE (Slack / Teams) ─────────────────────────────────────────

from xml.sax.saxutils import escape as xml_escape
import ipaddress
import socket
from urllib.parse import urlparse
from urllib3.util import parse_url as urllib3_parse_url


def _escape_xml(text: str) -> str:
    """Escape special XML characters to prevent XSS in TwiML responses.
    
    Escapes: < > & " '
    
    Args:
        text: The text to escape
        
    Returns:
        XML-safe text
    """
    if not text:
        return ""
    return xml_escape(str(text))


def _is_safe_url(url: str) -> bool:
    """Validate webhook URL to prevent SSRF attacks.
    
    Blocks:
    - Non-HTTP/HTTPS schemes
    - Private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    - Localhost (127.x.x.x, ::1) - except in development
    - Link-local addresses (169.254.x.x)
    - AWS metadata endpoint (169.254.169.254)
    - Internal hostnames (localhost, internal, etc.) - except in development
    
    Args:
        url: The webhook URL to validate
        
    Returns:
        True if URL is safe, False otherwise
    """
    if not url:
        return False
    
    try:
        parsed = urlparse(url)
        
        # Only allow HTTP and HTTPS schemes
        if parsed.scheme not in ('http', 'https'):
            logger.warning(f"Webhook URL blocked: invalid scheme '{parsed.scheme}'")
            return False
        
        hostname = parsed.hostname
        if not hostname:
            logger.warning("Webhook URL blocked: missing hostname")
            return False
        
        # Allow localhost in development mode
        is_development = settings.APP_ENV == "development"
        if is_development and hostname.lower() in ['localhost', '127.0.0.1', '::1']:
            logger.info(f"Webhook URL allowed (development): {url}")
            return True
        
        # Block localhost and common internal hostnames in production
        blocked_hostnames = ['localhost', 'internal', 'metadata', '169.254.169.254', '127.0.0.1', '::1']
        if hostname.lower() in blocked_hostnames or hostname.endswith('.internal'):
            logger.warning(f"Webhook URL blocked: internal hostname '{hostname}'")
            return False
        
        # Check if hostname is an IP address
        try:
            # Handle IPv4
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                logger.warning(f"Webhook URL blocked: private/internal IP '{hostname}'")
                return False
            return True  # Valid public IP
        except ValueError:
            pass  # Not an IP address, continue to DNS resolution check
        
        # Resolve hostname and check IP addresses
        # Use getaddrinfo to handle both IPv4 and IPv6
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        
        for info in addr_info:
            ip_str = info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    logger.warning(f"Webhook URL blocked: hostname resolves to private IP '{ip_str}'")
                    return False
            except ValueError:
                continue
        
        return True  # All resolved IPs are public
        
    except socket.gaierror:
        logger.warning(f"Webhook URL blocked: DNS resolution failed for '{url}'")
        return False
    except Exception as e:
        logger.warning(f"Webhook URL blocked: validation error '{url}' - {e}")
        return False


class WebhookService:
    def send_slack(self, webhook_url: str, message: str, title: str = "") -> dict:
        if not webhook_url:
            webhook_url = settings.SLACK_DEFAULT_WEBHOOK_URL
        if not webhook_url:
            logger.warning(f"[MOCK SLACK] Title: {title} | Message: {message[:50]}...")
            return {"status": "mock"}
        
        # Validate URL to prevent SSRF attacks
        if not _is_safe_url(webhook_url):
            logger.error(f"Slack webhook blocked: SSRF protection triggered for URL")
            return {"status": "blocked", "error": "Invalid webhook URL"}
        
        try:
            import httpx
            payload = {
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {title}"}},
                    {"type": "section", "text": {"type": "mrkdwn", "text": message}},
                ]
            }
            response = httpx.post(webhook_url, json=payload, timeout=10)
            return {"status": "sent" if response.status_code == 200 else "failed"}
        except Exception as e:
            logger.error(f"Slack webhook failed: {e}")
            return {"error": str(e), "status": "failed"}

    def send_teams(self, webhook_url: str, message: str, title: str = "") -> dict:
        if not webhook_url:
            webhook_url = settings.TEAMS_DEFAULT_WEBHOOK_URL
        if not webhook_url:
            logger.warning(f"[MOCK TEAMS] Title: {title} | Message: {message[:50]}...")
            return {"status": "mock"}
        
        # Validate URL to prevent SSRF attacks
        if not _is_safe_url(webhook_url):
            logger.error(f"Teams webhook blocked: SSRF protection triggered for URL")
            return {"status": "blocked", "error": "Invalid webhook URL"}
        
        try:
            import httpx
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "DC2626",
                "summary": title,
                "sections": [{"activityTitle": f"🚨 {title}", "activityText": message}]
            }
            response = httpx.post(webhook_url, json=payload, timeout=10)
            return {"status": "sent" if response.status_code == 200 else "failed"}
        except Exception as e:
            logger.error(f"Teams webhook failed: {e}")
            return {"error": str(e), "status": "failed"}


# Singletons
twilio_service = TwilioService()
email_service = EmailService()
webhook_service = WebhookService()
