from fastapi import APIRouter, Request, Depends, HTTPException, Query, Form
from fastapi.responses import Response, PlainTextResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Annotated, Optional, List
from urllib.parse import parse_qs
from twilio.request_validator import RequestValidator
from app.database import get_db
from app.core.deps import get_current_user
from app.config import settings
from app.models import (
    Notification,
    NotificationResponse,
    IncomingMessage,
    User,
    ResponseType,
    AlertChannel,
    DeliveryLog,
    DeliveryStatus,
    UserRole,
)
from app.schemas import IncomingMessageResponse
from datetime import datetime, timezone
import logging

# ─── CONTENT TYPE CONSTANTS ──────────────────────────────────────────────────
XML_CONTENT_TYPE = XML_CONTENT_TYPE


router = APIRouter(prefix="/webhooks", tags=["Webhooks"])
logger = logging.getLogger(__name__)


def _scrub_phone(phone: str) -> str:
    """Scrub phone for safe logging: +1-555-123-4567 → +15***4567"""
    if not phone or len(str(phone)) < 4:
        return "***"
    clean = ''.join(c for c in str(phone) if c.isdigit() or c == '+')
    if len(clean) <= 7:
        return clean[:3] + "***" if len(clean) > 3 else "***"
    return f"{clean[:3]}***{clean[-4:]}"


def _scrub_email(email: str) -> str:
    """Scrub email for safe logging: john.doe@example.com → jo***@example.com"""
    if not email or '@' not in email:
        return "***@***"
    local, domain = email.rsplit('@', 1)
    scrubbed_local = local + "***" if len(local) <= 2 else local[:2] + "***"
    return f"{scrubbed_local}@{domain}"


def _log_user_identity(user_id: Optional[int], email: Optional[str]) -> str:
    """Create safe user identity for logging: user_id=12345, email=jo***@example.com"""
    parts = []
    if user_id is not None:
        parts.append(f"user_id={user_id}")
    if email:
        parts.append(f"email={_scrub_email(email)}")
    return ", ".join(parts) if parts else "[UNKNOWN]"


async def validate_twilio_request(request: Request, body: bytes) -> bool:
    """Validate that the request actually came from Twilio using X-Twilio-Signature.

    Args:
        request: The incoming FastAPI request
        body: Raw request body bytes (must be read BEFORE form parsing)

    Returns:
        True if signature is valid, False otherwise
    """
    if not settings.TWILIO_AUTH_TOKEN:
        logger.error("TWILIO_AUTH_TOKEN not configured — cannot validate Twilio requests")
        return False

    validator = RequestValidator(settings.TWILIO_AUTH_TOKEN)

    signature = request.headers.get("X-Twilio-Signature", "")
    if not signature:
        logger.warning("Missing X-Twilio-Signature header")
        return False

    # Reconstruct the public URL that Twilio actually signed.
    # Behind Railway's reverse proxy, request.url shows http:// internally
    # but Twilio was given the public https:// URL via BACKEND_URL.
    if settings.BACKEND_URL:
        url = settings.BACKEND_URL.rstrip("/") + request.url.path
        if request.url.query:
            url += f"?{request.url.query}"
    else:
        url = str(request.url)

    # Parse raw body bytes into dict[str, str] for Twilio's validator.
    # RequestValidator.validate() expects dict, not bytes or raw string.
    params = {}
    if body:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        params = {k: v[0] for k, v in parsed.items()}

    is_valid = validator.validate(url, params, signature)

    if not is_valid:
        logger.warning(f"Invalid Twilio signature for URL: {url}")

    return is_valid


@router.post("/voice/response")
async def handle_voice_response(
    request: Request,
    db: Session = Depends(get_db),
):
    """Handle Twilio voice response when user presses 1 or 2."""
    # Read raw body FIRST (before any form parsing)
    body_bytes = await request.body()

    # Validate Twilio signature
    if not await validate_twilio_request(request, body_bytes):
        raise HTTPException(status_code=401, detail="Invalid Twilio signature")

    # Parse form data AFTER body read
    form_data = await request.form()
    From = form_data.get("From", "")
    To = form_data.get("To", "")
    Called = form_data.get("Called", "")
    Digits = form_data.get("Digits", "")
    CallSid = form_data.get("CallSid", "")

    try:
        logger.info(f"Voice response received: From={_scrub_phone(From)}, To={_scrub_phone(To)}, Digits={Digits}, CallSid={CallSid}")

        # Use To or Called parameter to find the user (the phone that received the call)
        # From will be the Twilio number, not the user's number
        user_phone = To or Called

        if not user_phone or not user_phone.strip():
            logger.error("No user phone number in voice webhook (To/Called missing)")
            twiml = """<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say>An error occurred. Please try again later.</Say>
</Response>"""
            return Response(content=twiml, media_type=XML_CONTENT_TYPE)

        # Normalize phone number for lookup
        user_phone_clean = user_phone.replace("+", "").replace("-", "").replace(" ", "").replace("(", "").replace(")", "")

        # Try multiple lookup strategies
        user = None

        # Strategy 1: Direct match (for E.164 format in DB)
        user = db.query(User).filter(User.phone == user_phone).first()

        # Strategy 2: Match without + prefix
        if not user:
            user = db.query(User).filter(User.phone == user_phone_clean).first()

        # Strategy 3: Match last 10 digits (for local format in DB)
        if not user and len(user_phone_clean) >= 10:
            last_10_digits = user_phone_clean[-10:]
            all_users_with_phones = db.query(User).filter(User.phone.isnot(None)).all()
            for u in all_users_with_phones:
                if u.phone:
                    u_clean = u.phone.replace("+", "").replace("-", "").replace(" ", "").replace("(", "").replace(")", "")
                    if u_clean.endswith(last_10_digits):
                        user = u
                        break

        if not user:
            logger.warning(f"Voice response from unknown number: {_scrub_phone(user_phone)}")
            twiml = """<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say>Thank you for your response.</Say>
</Response>"""
            return Response(content=twiml, media_type=XML_CONTENT_TYPE)

        logger.info(f"Voice response matched user: {_log_user_identity(user.id, user.email)} from phone {_scrub_phone(user_phone)}")

        # Map digits to response type
        response_type = None
        message = ""

        if Digits == "1":
            response_type = ResponseType.SAFE
            message = "You are marked as safe."
        elif Digits == "2":
            response_type = ResponseType.NEED_HELP
            message = "Help is on the way."
        elif not Digits:
            logger.warning(f"No digits received for call {CallSid}")
            twiml = """<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say>No input received. Goodbye.</Say>
</Response>"""
            return Response(content=twiml, media_type=XML_CONTENT_TYPE)
        else:
            logger.warning(f"Invalid digit received: {Digits} from user {user.id}")
            twiml = """<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say>Invalid option. Please press 1 or 2. Goodbye.</Say>
</Response>"""
            return Response(content=twiml, media_type=XML_CONTENT_TYPE)

        # Find the most recent active notification for this user
        notification = db.query(Notification).filter(
            Notification.status.in_(['sending', 'sent', 'scheduled'])
        ).order_by(desc(Notification.created_at)).first()

        # Record the response
        if notification and response_type:
            response = NotificationResponse(
                notification_id=notification.id,
                user_id=user.id,
                response_type=response_type,
                channel=AlertChannel.VOICE,
                from_number=From,
            )
            db.add(response)

            # Update delivery log if exists
            delivery_log = db.query(DeliveryLog).filter(
                DeliveryLog.notification_id == notification.id,
                DeliveryLog.user_id == user.id,
                DeliveryLog.channel == AlertChannel.VOICE
            ).first()

            if delivery_log:
                delivery_log.status = DeliveryStatus.DELIVERED

            db.commit()
            logger.info(f"Voice response recorded: User {user.id} - {response_type.value} for Notification {notification.id}")
        else:
            # Create incoming message record if no active notification
            incoming = IncomingMessage(
                user_id=user.id,
                from_number=From,
                body=f"Voice response: {Digits}",
                channel=AlertChannel.VOICE,
            )
            db.add(incoming)
            db.commit()
            logger.info(f"Voice response recorded as incoming message: User {user.id} - {Digits}")

        # Return TwiML response
        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say>{message}</Say>
</Response>"""

        return Response(content=twiml, media_type=XML_CONTENT_TYPE)

    except Exception as e:
        logger.error(f"Error processing voice response: {e}", exc_info=True)
        twiml = """<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say>An error occurred. Please try again later.</Say>
</Response>"""
        return Response(content=twiml, media_type=XML_CONTENT_TYPE)


@router.post("/voice/status")
async def handle_voice_status(
    request: Request,
    db: Session = Depends(get_db),
):
    """Handle Twilio voice call status callbacks.

    This endpoint receives status updates about the call (completed, failed, etc.)
    """
    # Read raw body FIRST (before any form parsing)
    body_bytes = await request.body()

    # Validate Twilio signature
    if not await validate_twilio_request(request, body_bytes):
        raise HTTPException(status_code=401, detail="Invalid Twilio signature")

    # Parse form data AFTER body read
    form_data = await request.form()
    CallSid = form_data.get("CallSid", "")
    CallStatus = form_data.get("CallStatus", "")
    From = form_data.get("From", "")

    logger.info(f"Voice status update: CallSid={CallSid}, Status={CallStatus}, From={_scrub_phone(From)}")

    # Update delivery log using external_id (where Twilio CallSid is stored)
    if CallSid:
        delivery_log = db.query(DeliveryLog).filter(
            DeliveryLog.external_id == CallSid
        ).first()

        if delivery_log:
            if CallStatus == "completed":
                delivery_log.status = DeliveryStatus.DELIVERED
            elif CallStatus in ["failed", "busy", "no-answer"]:
                delivery_log.status = DeliveryStatus.FAILED
            db.commit()
            logger.info(f"Voice call status updated: {CallStatus} for delivery_log {delivery_log.id}")

    # Always return 200 to Twilio
    return Response(status_code=200)


@router.get("/incoming-messages", response_model=List[IncomingMessageResponse])
def get_incoming_messages(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """View incoming messages and voice responses (authenticated users only).

    Args:
        limit: Maximum number of results (1-500, default 50)

    Access Control:
        - Manager and Admin roles: Can see all incoming messages
        - Viewer role: Can only see their own incoming messages
    """
    # Get incoming messages
    incoming_query = (
        db.query(IncomingMessage)
        .outerjoin(User, IncomingMessage.user_id == User.id)
    )
    
    # Get voice responses
    voice_query = (
        db.query(NotificationResponse, Notification, User)
        .join(Notification, NotificationResponse.notification_id == Notification.id)
        .join(User, NotificationResponse.user_id == User.id)
        .filter(NotificationResponse.channel == 'voice')
    )
    
    # Viewer-role users can only see their own messages
    if current_user.role == UserRole.VIEWER:
        incoming_query = incoming_query.filter(IncomingMessage.user_id == current_user.id)
        voice_query = voice_query.filter(NotificationResponse.user_id == current_user.id)
    
    # Order and limit incoming messages
    incoming_messages = (
        incoming_query
        .order_by(desc(IncomingMessage.received_at))
        .limit(limit)
        .all()
    )
    
    # Order and limit voice responses
    voice_responses = (
        voice_query
        .order_by(desc(NotificationResponse.responded_at))
        .limit(limit)
        .all()
    )
    
    # Combine and format results
    result = []
    
    # Add incoming messages
    for msg in incoming_messages:
        result.append({
            "id": msg.id,
            "from_number": msg.from_number,
            "body": msg.body,
            "channel": msg.channel,
            "user_id": msg.user_id,
            "user_email": msg.user.email if msg.user else msg.user_email,
            "user_name": msg.user.full_name if msg.user else None,
            "notification_id": msg.notification_id,
            "is_processed": msg.is_processed,
            "received_at": msg.received_at,
        })
    
    # Add voice responses
    for response, notification, user in voice_responses:
        result.append({
            "id": f"voice_{response.id}",
            "from_number": user.phone or "",
            "body": f"Voice response: {response.response_type.value}",
            "channel": "voice",
            "user_id": user.id,
            "user_email": user.email,
            "user_name": user.full_name,
            "notification_id": response.notification_id,
            "is_processed": True,
            "received_at": response.responded_at,
        })
    
    # Sort by received_at descending
    result.sort(key=lambda x: x["received_at"], reverse=True)

    # Limit results
    return result[:limit]