from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import desc, update
from typing import Optional, List
from app.database import get_db
from app.core.deps import get_current_user, require_manager
from app.models import (
    Notification, NotificationResponse, IncomingMessage,
    User, ResponseType, AlertChannel, DeliveryLog, DeliveryStatus
)
from app.schemas import IncomingMessageResponse
from datetime import datetime, timezone
import logging

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])
logger = logging.getLogger(__name__)


def _find_user_by_phone(db: Session, phone_number: str) -> Optional[User]:
    """Find user by phone number with proper validation.
    
    Handles various phone formats: +1234567890, 1234567890, (123) 456-7890
    Returns None if phone number is empty, invalid, or ambiguous (multiple matches).
    """
    if not phone_number or not phone_number.strip():
        return None
    
    # Clean and extract digits
    phone_clean = ''.join(c for c in phone_number if c.isdigit())
    
    if len(phone_clean) < 10:
        logger.warning(f"Invalid phone number format: {phone_number}")
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
    matches = db.query(User).filter(
        User.phone.ilike(f"%{last_10}")  # Ends with last 10 digits
    ).all()
    
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
    From: str = Form(...),
    To: str = Form(...),
    Body: str = Form(""),
    MessageSid: str = Form(""),
    db: Session = Depends(get_db)
):
    """Handle inbound SMS from Twilio - employees replying SAFE/HELP/1/2"""
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
        latest_log = db.query(DeliveryLog).filter(
            DeliveryLog.user_id == user.id,
            DeliveryLog.channel == AlertChannel.SMS
        ).order_by(desc(DeliveryLog.created_at)).first()
        if latest_log:
            notification = latest_log.notification

    # Save incoming message
    incoming = IncomingMessage(
        from_number=From,
        to_number=To,
        body=Body,
        channel=AlertChannel.SMS,
        user_id=user.id if user else None,
        notification_id=notification.id if notification else None,
        is_processed=True
    )
    db.add(incoming)

    # Save response
    if notification:
        resp = NotificationResponse(
            notification_id=notification.id,
            user_id=user.id if user else None,
            channel=AlertChannel.SMS,
            response_type=response_type,
            message=Body if response_type == ResponseType.CUSTOM else None,
            from_number=From
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

    twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Message>{reply}</Message>
</Response>"""
    return Response(content=twiml, media_type="application/xml")


@router.post("/sms/status")
async def sms_status_callback(
    request: Request,
    MessageSid: str = Form(""),
    MessageStatus: str = Form(""),
    To: str = Form(""),
    db: Session = Depends(get_db)
):
    """Twilio delivery status callback for outbound SMS."""
    logger.info(f"SMS status update: {MessageSid} -> {MessageStatus}")

    if MessageSid:
        log = db.query(DeliveryLog).filter(DeliveryLog.external_id == MessageSid).first()
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


@router.post("/voice/response")
async def voice_response(
    request: Request,
    Digits: str = Form(""),
    CallSid: str = Form(""),
    From: str = Form(""),
    db: Session = Depends(get_db)
):
    """Handle keypress response from voice calls - 1=Safe, 2=Help."""
    try:
        logger.info(f"Voice response from {From}: pressed {Digits}, CallSid: {CallSid}")

        response_type = ResponseType.SAFE if Digits == "1" else ResponseType.NEED_HELP if Digits == "2" else ResponseType.ACKNOWLEDGED

        # Find user by phone with proper validation (prevents matching empty From)
        user = _find_user_by_phone(db, From)
        logger.info(f"User found: {user.email if user else 'None'}")

        latest_log = None
        if user:
            latest_log = db.query(DeliveryLog).filter(
                DeliveryLog.user_id == user.id,
                DeliveryLog.channel == AlertChannel.VOICE
            ).order_by(desc(DeliveryLog.created_at)).first()
            logger.info(f"Latest voice log: {latest_log.notification_id if latest_log else 'None'}")

        if latest_log:
            resp = NotificationResponse(
                notification_id=latest_log.notification_id,
                user_id=user.id if user else None,
                channel=AlertChannel.VOICE,
                response_type=response_type,
                from_number=From
            )
            db.add(resp)
            db.commit()
            logger.info(f"Response saved: {response_type.value}")

        if response_type == ResponseType.SAFE:
            message = "Thank you. Your safe status has been recorded. Goodbye."
        elif response_type == ResponseType.NEED_HELP:
            message = "Help request recorded. Emergency team has been notified. Please stay where you are."
        else:
            message = "Response recorded. Thank you."

        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">{message}</Say>
</Response>"""
        return Response(content=twiml, media_type="application/xml")
    
    except Exception as e:
        logger.error(f"Voice response error: {str(e)}", exc_info=True)
        # Return error TwiML
        twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Say voice="alice">Sorry, an error occurred. Please try again later.</Say>
</Response>"""
        return Response(content=twiml, media_type="application/xml")


@router.get("/incoming-messages", response_model=List[IncomingMessageResponse])
def get_incoming_messages(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """View incoming messages (authenticated users only)."""
    # Query with user relationship to include user_name in response
    messages = db.query(IncomingMessage).outerjoin(
        User, IncomingMessage.user_id == User.id
    ).order_by(
        desc(IncomingMessage.received_at)
    ).limit(limit).all()
    
    # Build response with user_name from related user
    result = []
    for msg in messages:
        result.append({
            "id": msg.id,
            "from_number": msg.from_number,
            "body": msg.body,
            "channel": msg.channel,
            "user_id": msg.user_id,
            "user_name": msg.user.full_name if msg.user else None,
            "notification_id": msg.notification_id,
            "is_processed": msg.is_processed,
            "received_at": msg.received_at
        })
    
    return result
