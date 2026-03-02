import logging
from datetime import datetime, timezone
from typing import List
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import (
    Notification, NotificationStatus, DeliveryLog, DeliveryStatus,
    AlertChannel, User
)
from app.services.messaging import twilio_service, email_service, webhook_service
from sqlalchemy import update   

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def send_notification_task(self, notification_id: int):
    """Main task to dispatch a notification to all recipients across all channels."""
    db = SessionLocal()
    try:
        notification = db.query(Notification).filter(Notification.id == notification_id).first()
        if not notification:
            logger.error(f"Notification {notification_id} not found")
            return

        notification.status = NotificationStatus.SENDING
        db.commit()

        # Build recipient list
        recipients = _get_recipients(db, notification)
        notification.total_recipients = len(recipients)
        db.commit()

        if not recipients:
            notification.status = NotificationStatus.SENT
            notification.sent_at = datetime.now(timezone.utc)
            db.commit()
            return

        # Dispatch per recipient per channel
        for user in recipients:
            for channel in notification.channels:
                _send_to_channel.delay(notification_id, user.id, channel)

        notification.status = NotificationStatus.SENT
        notification.sent_at = datetime.now(timezone.utc)
        db.commit()

        # Send to webhooks (not per-user)
        if AlertChannel.SLACK in notification.channels and notification.slack_webhook_url:
            webhook_service.send_slack(
                notification.slack_webhook_url,
                notification.message,
                notification.title
            )
        if AlertChannel.TEAMS in notification.channels and notification.teams_webhook_url:
            webhook_service.send_teams(
                notification.teams_webhook_url,
                notification.message,
                notification.title
            )

        logger.info(f"Notification {notification_id} dispatched to {len(recipients)} recipients")

    except Exception as e:
        logger.error(f"Error dispatching notification {notification_id}: {e}")
        if notification:
            notification.status = NotificationStatus.FAILED
            db.commit()
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def _send_to_channel(self, notification_id: int, user_id: int, channel: str):
    """Send notification to a single user via a single channel."""
    db = SessionLocal()
    try:
        notification = db.query(Notification).filter(Notification.id == notification_id).first()
        user = db.query(User).filter(User.id == user_id).first()

        if not notification or not user:
            return

        log = DeliveryLog(
            notification_id=notification_id,
            user_id=user_id,
            channel=channel,
            status=DeliveryStatus.PENDING,
            sent_at=datetime.now(timezone.utc)
        )

        result = {}

        if channel == AlertChannel.SMS:
            if user.phone:
                log.to_address = user.phone
                result = twilio_service.send_sms(user.phone, notification.message)
            else:
                log.status = DeliveryStatus.FAILED
                log.error_message = "No phone number"
                db.add(log)
                db.commit()
                return

        elif channel == AlertChannel.EMAIL:
            if user.email:
                log.to_address = user.email
                subject = notification.subject or notification.title
                result = email_service.send_email(user.email, subject, notification.message)
            else:
                log.status = DeliveryStatus.FAILED
                log.error_message = "No email address"
                db.add(log)
                db.commit()
                return

        elif channel == AlertChannel.VOICE:
            if user.phone:
                log.to_address = user.phone
                result = twilio_service.make_voice_call(user.phone, notification.message)
            else:
                log.status = DeliveryStatus.FAILED
                log.error_message = "No phone number for voice call"
                db.add(log)
                db.commit()
                return

        elif channel == AlertChannel.WHATSAPP:
            number = user.whatsapp_number or user.phone
            if number:
                log.to_address = number
                result = twilio_service.send_whatsapp(number, notification.message)
            else:
                log.status = DeliveryStatus.FAILED
                log.error_message = "No WhatsApp number"
                db.add(log)
                db.commit()
                return

        # Update log based on result
        if result.get("error"):
            log.status = DeliveryStatus.FAILED
            log.error_message = result["error"]
            db.add(log)
            db.commit()
            # Atomic increment to avoid race condition
            db.execute(
                update(Notification)
                .where(Notification.id == notification_id)
                .values(failed_count=Notification.failed_count + 1)
            )
            db.commit()
        else:
            log.status = DeliveryStatus.SENT
            log.external_id = result.get("sid") or result.get("message_id")
            db.add(log)
            db.commit()
            # Atomic increment to avoid race condition
            db.execute(
                update(Notification)
                .where(Notification.id == notification_id)
                .values(sent_count=Notification.sent_count + 1)
            )
            db.commit()

    except Exception as e:
        logger.error(f"Error sending to user {user_id} via {channel}: {e}")
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task
def process_scheduled_notifications():
    """Check for scheduled notifications that are due and dispatch them."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due_notifications = db.query(Notification).filter(
            Notification.status == NotificationStatus.SCHEDULED,
            Notification.scheduled_at <= now
        ).all()

        for notification in due_notifications:
            logger.info(f"Dispatching scheduled notification {notification.id}")
            send_notification_task.delay(notification.id)

        if due_notifications:
            logger.info(f"Dispatched {len(due_notifications)} scheduled notifications")
    finally:
        db.close()


def _get_recipients(db, notification: Notification) -> List[User]:
    """Build unique recipient list from target_all, groups, and individual users."""
    recipient_ids = set()

    if notification.target_all:
        users = db.query(User).filter(
            User.is_active == True,
            User.deleted_at == None
        ).all()
        return users

    for group in notification.target_groups:
        if group.type == "dynamic" and group.dynamic_filter:
            query = db.query(User).filter(User.is_active == True, User.deleted_at == None)
            f = group.dynamic_filter
            if f.get("department"):
                query = query.filter(User.department == f["department"])
            if f.get("location_id"):
                query = query.filter(User.location_id == f["location_id"])
            users = query.all()
        else:
            users = group.members

        for u in users:
            if u.id not in recipient_ids:
                recipient_ids.add(u.id)

    for user in notification.target_users:
        recipient_ids.add(user.id)

    if not recipient_ids:
        return []

    return db.query(User).filter(
        User.id.in_(recipient_ids),
        User.is_active == True,
        User.deleted_at == None
    ).all()
