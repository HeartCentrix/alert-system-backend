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
    Returns None if phone number is empty or no match found.
    """
    if not phone_number or not phone_number.strip():
        return None
    
    # Clean and extract last 10 digits for matching
    phone_clean = ''.join(c for c in phone_number if c.isdigit())
    
    if len(phone_clean) < 10:
        logger.warning(f"Invalid phone number format: {phone_number}")
        return None
    
    # Get last 10 digits for matching (handles country codes)
    last_10 = phone_clean[-10:]
    
    # Try multiple matching strategies
    phone_variants = [
        phone_number,  # Original format
        f"+{phone_clean}",  # With + prefix
        phone_clean,  # Digits only
        last_10,  # Last 10 digits
    ]
    
    for ph in phone_variants:
        if ph and len(ph) >= 10:
            user = db.query(User).filter(User.phone.contains(ph[-10:])).first()
            if user:
                return user
    
    return None


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
    logger.info(f"Voice response from {From}: pressed {Digits}")

    response_type = ResponseType.SAFE if Digits == "1" else ResponseType.NEED_HELP if Digits == "2" else ResponseType.ACKNOWLEDGED

    # Find user by phone with proper validation (prevents matching empty From)
    user = _find_user_by_phone(db, From)

    latest_log = None
    if user:
        latest_log = db.query(DeliveryLog).filter(
            DeliveryLog.user_id == user.id,
            DeliveryLog.channel == AlertChannel.VOICE
        ).order_by(desc(DeliveryLog.created_at)).first()

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


@router.get("/incoming-messages", response_model=List[IncomingMessageResponse])
def get_incoming_messages(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """View incoming messages (authenticated users only)."""
    messages = db.query(IncomingMessage).order_by(
        desc(IncomingMessage.received_at)
    ).limit(limit).all()
    return messages
