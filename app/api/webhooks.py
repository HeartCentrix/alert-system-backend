from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import desc, update
from typing import Optional, List
from app.database import get_db
from app.core.deps import get_current_user, require_manager
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
)
from app.schemas import IncomingMessageResponse
from datetime import datetime, timezone
import logging
from xml.sax.saxutils import escape as xml_escape
from urllib.parse import parse_qs
from twilio.request_validator import RequestValidator

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])
logger = logging.getLogger(__name__)


def validate_twilio_request(request: Request, body: bytes) -> bool:
    """Validate Twilio request signature to prevent unauthorized access.
    
    Args:
        request: The incoming FastAPI request
        body: Raw request body bytes
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not settings.TWILIO_AUTH_TOKEN:
        logger.error("TWILIO_AUTH_TOKEN not configured - cannot validate Twilio requests")
        return False
    
    validator = RequestValidator(settings.TWILIO_AUTH_TOKEN)
    
    # Get the signature from headers
    signature = request.headers.get("X-Twilio-Signature", "")
    if not signature:
        logger.warning("Missing X-Twilio-Signature header")
        return False
    
    # Reconstruct the URL (Twilio signs the full URL including query params)
    url = str(request.url)
    
    # Parse raw body bytes into a dict of str->str params
    # Twilio's RequestValidator.validate() expects a dict, not raw bytes
    params = {}
    if body:
        body_str = body.decode("utf-8")
        parsed = parse_qs(body_str, keep_blank_values=True)
        # parse_qs returns lists; Twilio expects single string values
        params = {k: v[0] for k, v in parsed.items()}
    
    # Validate the signature
    is_valid = validator.validate(url, params, signature)
    
    if not is_valid:
        logger.warning(f"Invalid Twilio signature for URL: {url}")
    
    return is_valid


def _find_user_by_phone(db: Session, phone_number: str) -> Optional[User]:
    """Find user by phone number with proper validation.

    Handles various phone formats: +1234567890, 1234567890, (123) 456-7890
    Returns None if phone number is empty, invalid, or ambiguous (multiple matches).
    
    Security: Prevents matching all users when phone number is empty or missing.
    """
    # Reject empty, whitespace-only, or None phone numbers immediately
    # This prevents matching all users with NULL/empty phone fields
    if not phone_number or not phone_number.strip():
        logger.warning("Empty phone number provided - cannot lookup user")
        return None

    # Clean and extract digits only
    phone_clean = "".join(c for c in phone_number if c.isdigit())

    # Require at least 10 digits for a valid phone number
    if len(phone_clean) < 10:
        logger.warning(f"Invalid phone number format (too short): '{phone_number}' (cleaned: '{phone_clean}')")
        return None

    # Get last 10 digits for matching (handles country codes)
    last_10 = phone_clean[-10:]

    # Strategy 1: Try exact match on full cleaned number (most precise)
    exact_match = db.query(User).filter(User.phone == phone_clean).first()
    if exact_match:
        return exact_match

    # Strategy 2: Try match with + prefix
    with_plus = f"+{phone_clean}"
    exact_match = db.query(User).filter(User.phone == with_plus).first()
    if exact_match:
        return exact_match

    # Strategy 3: Match by last 10 digits - but check for AMBIGUOUS matches
    # This prevents matching wrong user when multiple have same last 10 digits
    matches = (
        db.query(User)
        .filter(User.phone.ilike(f"%{last_10}"))  # Ends with last 10 digits
        .all()
    )

    if len(matches) == 1:
        return matches[0]  # Unambiguous match
    elif len(matches) > 1:
        # AMBIGUOUS - multiple users have numbers ending in same 10 digits
        logger.warning(
            f"Ambiguous phone match for {phone_number} (last 10: {last_10}). "
            f"Found {len(matches)} users: {[u.email for u in matches]}. "
            "Cannot determine correct user - response not recorded."
        )
        return None  # Don't guess - better to fail than match wrong user

    return None  # No match found


@router.post("/sms/inbound")
async def sms_inbound(
    request: Request,
    db: Session = Depends(get_db),
):
    """Handle inbound SMS from Twilio - employees replying SAFE/HELP/1/2"""
    # Read body FIRST (before any form parsing) to avoid "Stream consumed" error
    body_bytes = await request.body()
    if not validate_twilio_request(request, body_bytes):
        raise HTTPException(status_code=401, detail="Invalid Twilio signature")

    # Parse form data from the raw body bytes (stream already consumed above)
    body_str = body_bytes.decode("utf-8")
    form_data = parse_qs(body_str, keep_blank_values=True)
    # parse_qs returns lists, extract single values
    From = form_data.get("From", [""])[0]
    To = form_data.get("To", [""])[0]
    Body = form_data.get("Body", [""])[0]
    MessageSid = form_data.get("MessageSid", [""])[0]

    logger.info(f"Inbound SMS from {From}: {Body}")

    body_clean = Body.strip().upper()

    # Map reply to response type
    response_type = None
    if body_clean in ["1", "SAFE", "YES", "OK", "I AM SAFE"]:
        response_type = ResponseType.SAFE
    elif body_clean in ["2", "HELP", "SOS", "NEED HELP", "EMERGENCY"]:
        response_type = ResponseType.NEED_HELP
    else:
        response_type = ResponseType.CUSTOM

    # Find the user by phone
    user = _find_user_by_phone(db, From)

    # Find the most recent active notification sent to this user
    notification = None
    if user:
        latest_log = (
            db.query(DeliveryLog)
            .filter(
                DeliveryLog.user_id == user.id, DeliveryLog.channel == AlertChannel.SMS
            )
            .order_by(desc(DeliveryLog.created_at))
            .first()
        )
        if latest_log:
            notification = latest_log.notification

    # Save incoming message
    incoming = IncomingMessage(
        from_number=From,
        to_number=To,
        body=Body,
        channel=AlertChannel.SMS,
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        notification_id=notification.id if notification else None,
        is_processed=True,
    )
    db.add(incoming)

    # Save response
    if notification:
        resp = NotificationResponse(
            notification_id=notification.id,
            user_id=user.id if user else None,
            user_email=user.email if user else None,
            channel=AlertChannel.SMS,
            response_type=response_type,
            message=Body if response_type == ResponseType.CUSTOM else None,
            from_number=From,
        )
        db.add(resp)

    db.commit()

    # Reply TwiML
    if response_type == ResponseType.SAFE:
        reply = "Thank you! Your safety status has been recorded as SAFE. Stay safe."
    elif response_type == ResponseType.NEED_HELP:
        reply = "HELP request received. Emergency response team has been notified. Stay where you are."
    else:
        reply = "Message received. Reply SAFE (1) if you are okay, or HELP (2) if you need assistance."

    # Escape reply to prevent XSS in TwiML (even for hardcoded messages - defense in depth)
    safe_reply = xml_escape(reply)
    twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Message>{safe_reply}</Message>
</Response>"""
    return Response(content=twiml, media_type="text/xml")


@router.post("/sms/status")
async def sms_status_callback(
    request: Request,
    db: Session = Depends(get_db),
):
    """Twilio delivery status callback for outbound SMS."""
    # Read body FIRST (before any form parsing) to avoid "Stream consumed" error
    body_bytes = await request.body()
    if not validate_twilio_request(request, body_bytes):
        raise HTTPException(status_code=401, detail="Invalid Twilio signature")

    # Parse form data from the raw body bytes (stream already consumed above)
    body_str = body_bytes.decode("utf-8")
    form_data = parse_qs(body_str, keep_blank_values=True)
    MessageSid = form_data.get("MessageSid", [""])[0]
    MessageStatus = form_data.get("MessageStatus", [""])[0]
    To = form_data.get("To", [""])[0]
    
    logger.info(f"SMS status update: {MessageSid} -> {MessageStatus}")

    if MessageSid:
        log = (
            db.query(DeliveryLog).filter(DeliveryLog.external_id == MessageSid).first()
        )
        if log:
            status_map = {
                "delivered": DeliveryStatus.DELIVERED,
                "undelivered": DeliveryStatus.FAILED,
                "failed": DeliveryStatus.FAILED,
                "sent": DeliveryStatus.SENT,
            }
            new_status = status_map.get(MessageStatus.lower())
            if new_status:
                log.status = new_status
                if new_status == DeliveryStatus.DELIVERED:
                    log.delivered_at = datetime.now(timezone.utc)
                    # Update notification delivered_count atomically to avoid race condition
                    db.execute(
                        update(Notification)
                        .where(Notification.id == log.notification_id)
                        .values(delivered_count=Notification.delivered_count + 1)
                    )
            db.commit()

    return Response(content="", status_code=200)


@router.post("/voice/status")
async def voice_status_callback(
    request: Request,
    db: Session = Depends(get_db),
):
    """Twilio call status callback for outbound voice calls."""
    # Read body FIRST (before any form parsing) to avoid "Stream consumed" error
    body_bytes = await request.body()
    if not validate_twilio_request(request, body_bytes):
        raise HTTPException(status_code=401, detail="Invalid Twilio signature")

    # Parse form data from the raw body bytes (stream already consumed above)
    body_str = body_bytes.decode("utf-8")
    form_data = parse_qs(body_str, keep_blank_values=True)
    CallSid = form_data.get("CallSid", [""])[0]
    CallStatus = form_data.get("CallStatus", [""])[0]
    To = form_data.get("To", [""])[0]
    From = form_data.get("From", [""])[0]
    Duration = form_data.get("Duration", [""])[0]

    logger.info(f"Voice status: {CallSid} -> {CallStatus}, Duration: {Duration}s")

    if CallSid:
        log = (
            db.query(DeliveryLog)
            .filter(DeliveryLog.external_id == CallSid)
            .first()
        )
        if log:
            status_map = {
                "completed": DeliveryStatus.DELIVERED,
                "answered": DeliveryStatus.DELIVERED,
                "busy": DeliveryStatus.FAILED,
                "failed": DeliveryStatus.FAILED,
                "no-answer": DeliveryStatus.FAILED,
                "canceled": DeliveryStatus.FAILED,
                "ringing": DeliveryStatus.SENT,
            }
            new_status = status_map.get(CallStatus.lower())
            if new_status:
                log.status = new_status
                if new_status == DeliveryStatus.DELIVERED:
                    log.delivered_at = datetime.now(timezone.utc)
                    # Update notification delivered_count atomically
                    db.execute(
                        update(Notification)
                        .where(Notification.id == log.notification_id)
                        .values(delivered_count=Notification.delivered_count + 1)
                    )
                elif new_status == DeliveryStatus.FAILED:
                    log.failed_at = datetime.now(timezone.utc)
                    log.error_message = f"Call status: {CallStatus}"
                db.commit()
                logger.info(f"Voice log updated: {log.id} -> {new_status.value}")

    return Response(content="", status_code=200)


@router.post("/voice/response")
async def voice_response(
    request: Request,
    db: Session = Depends(get_db),
):
    """Handle keypress response from voice calls - 1=Safe, 2=Help."""
    # Read body FIRST (before any form parsing) to avoid "Stream consumed" error
    body_bytes = await request.body()
    if not validate_twilio_request(request, body_bytes):
        raise HTTPException(status_code=401, detail="Invalid Twilio signature")

    try:
        # Parse form data from the raw body bytes (stream already consumed above)
        body_str = body_bytes.decode("utf-8")
        form_data = parse_qs(body_str, keep_blank_values=True)
        Digits = form_data.get("Digits", [""])[0]
        CallSid = form_data.get("CallSid", [""])[0]
        From = form_data.get("From", [""])[0]
        
        logger.info(f"Parsed form data - From: {From}, Digits: '{Digits}', CallSid: {CallSid}")

        # Save incoming message to DB (even if no user found - for tracking)
        user = _find_user_by_phone(db, From)
        logger.info(f"User found: {user.email if user else 'None'}")

        # Find the most recent voice delivery log for this user
        latest_log = None
        if user:
            latest_log = (
                db.query(DeliveryLog)
                .filter(
                    DeliveryLog.user_id == user.id,
                    DeliveryLog.channel == AlertChannel.VOICE
                )
                .order_by(desc(DeliveryLog.created_at))
                .first()
            )
            logger.info(
                f"Latest voice log: notification_id={latest_log.notification_id if latest_log else 'None'}"
            )

        # Determine response type based on keypress
        response_type = ResponseType.ACKNOWLEDGED
        if Digits == "1":
            response_type = ResponseType.SAFE
        elif Digits == "2":
            response_type = ResponseType.NEED_HELP

        logger.info(f"Response type determined: {response_type.value}")

        # Save incoming message to DB
        incoming = IncomingMessage(
            from_number=From,
            to_number=settings.TWILIO_FROM_NUMBER,
            body=f"Keypress: {Digits}" if Digits else "Voice call response",
            channel=AlertChannel.VOICE,
            user_id=user.id if user else None,
            user_email=user.email if user else None,
            notification_id=latest_log.notification_id if latest_log else None,
            is_processed=True,
        )
        db.add(incoming)
        logger.info(f"IncomingMessage added to session: id={incoming.id}, channel=VOICE, from={From}")

        # Save response if we have a notification
        if latest_log and latest_log.notification_id:
            resp = NotificationResponse(
                notification_id=latest_log.notification_id,
                user_id=user.id if user else None,
                user_email=user.email if user else None,
                channel=AlertChannel.VOICE,
                response_type=response_type,
                from_number=From,
            )
            db.add(resp)
            logger.info(f"NotificationResponse added to session: id={resp.id}, type={response_type.value}")
        else:
            logger.warning(f"No notification found for voice response from {From}")

        logger.info(f"About to commit to database...")
        db.commit()
        logger.info(f"=== Voice response COMMITTED to DB successfully ===")
        logger.info(f"IncomingMessage.id={incoming.id}, NotificationResponse.id={resp.id if latest_log else 'N/A'}")

        if response_type == ResponseType.SAFE:
            message = "Thank you. Your safe status has been recorded. Goodbye."
        elif response_type == ResponseType.NEED_HELP:
            message = "Help request recorded. Emergency team has been notified. Please stay where you are."
        else:
            message = "Response recorded. Thank you."

        # Escape message to prevent XSS in TwiML
        safe_message = xml_escape(message)
        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">{safe_message}</Say>
</Response>"""
        return Response(content=twiml, media_type="text/xml")

    except Exception as e:
        logger.error(f"=== VOICE WEBHOOK ERROR ===", exc_info=True)
        logger.error(f"Error details: {str(e)}")
        db.rollback()
        # Return error TwiML
        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">Sorry, an error occurred. Please try again later.</Say>
</Response>"""
        return Response(content=twiml, media_type="text/xml")


@router.get("/incoming-messages", response_model=List[IncomingMessageResponse])
def get_incoming_messages(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """View incoming messages (authenticated users only)."""
    # Query with user relationship to include user_name in response
    messages = (
        db.query(IncomingMessage)
        .outerjoin(User, IncomingMessage.user_id == User.id)
        .order_by(desc(IncomingMessage.received_at))
        .limit(limit)
        .all()
    )

    # Build response with user_name from related user
    result = []
    for msg in messages:
        result.append(
            {
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
            }
        )

    return result
