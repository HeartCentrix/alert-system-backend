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
    """Main task to dispatch a notification to all recipients across all channels.
    
    Sets notification status to:
    - SENT: All deliveries successful
    - PARTIALLY_SENT: Some deliveries failed
    - FAILED: All deliveries failed or zero recipients
    """
    db = SessionLocal()
    notification = None
    try:
        notification = db.query(Notification).filter(Notification.id == notification_id).first()
        if not notification:
            logger.error(f"Notification {notification_id} not found")
            return

        # Prevent re-processing if already sent
        if notification.status in [NotificationStatus.SENT, NotificationStatus.PARTIALLY_SENT]:
            logger.info(f"Notification {notification_id} already processed (status={notification.status})")
            return

        notification.status = NotificationStatus.SENDING
        db.commit()

        # Build recipient list
        recipients = _get_recipients(db, notification)
        notification.total_recipients = len(recipients)
        db.commit()

        if not recipients:
            # No recipients found - mark as FAILED with clear error
            notification.status = NotificationStatus.FAILED
            notification.sent_at = datetime.now(timezone.utc)
            db.commit()
            logger.warning(f"Notification {notification_id} has zero recipients - marked as FAILED")
            return

        # Dispatch per recipient per channel (skip if already sent)
        dispatched_count = 0
        for user in recipients:
            for channel in notification.channels:
                # Check if already dispatched to avoid duplicates on retry
                existing_log = db.query(DeliveryLog).filter(
                    DeliveryLog.notification_id == notification_id,
                    DeliveryLog.user_id == user.id,
                    DeliveryLog.channel == channel
                ).first()

                if not existing_log:
                    _send_to_channel.delay(notification_id, user.id, channel)
                    dispatched_count += 1

        # Status will be updated by _send_to_channel tasks based on delivery results
        # Final status determined after all subtasks complete (handled in _send_to_channel)
        notification.status = NotificationStatus.SENDING  # Keep as SENDING until subtasks complete
        notification.sent_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(f"Notification {notification_id}: dispatched {dispatched_count} subtasks to {len(recipients)} recipients")

        # Send to webhooks AFTER marking notification as SENT (webhook failure won't trigger retry)
        webhook_errors = []
        if AlertChannel.SLACK in notification.channels and notification.slack_webhook_url:
            try:
                webhook_service.send_slack(
                    notification.slack_webhook_url,
                    notification.message,
                    notification.title
                )
            except Exception as e:
                logger.error(f"Slack webhook failed for notification {notification_id}: {e}")
                webhook_errors.append(f"Slack: {e}")

        if AlertChannel.TEAMS in notification.channels and notification.teams_webhook_url:
            try:
                webhook_service.send_teams(
                    notification.teams_webhook_url,
                    notification.message,
                    notification.title
                )
            except Exception as e:
                logger.error(f"Teams webhook failed for notification {notification_id}: {e}")
                webhook_errors.append(f"Teams: {e}")

        if webhook_errors:
            logger.warning(f"Notification {notification_id} sent successfully but webhooks failed: {webhook_errors}")

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

        # Idempotency check: skip if already processed (prevents duplicates on retry)
        existing_log = db.query(DeliveryLog).filter(
            DeliveryLog.notification_id == notification_id,
            DeliveryLog.user_id == user_id,
            DeliveryLog.channel == channel
        ).first()
        
        if existing_log and existing_log.status in [DeliveryStatus.SENT, DeliveryStatus.DELIVERED]:
            logger.info(f"Notification {notification_id} to user {user_id} via {channel} already sent, skipping duplicate")
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
            # Update notification status based on delivery results
            _update_notification_status(db, notification_id)
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
            # Update notification status based on delivery results
            _update_notification_status(db, notification_id)

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
        
        # Atomically claim due notifications to prevent duplicate dispatch
        # Update status from SCHEDULED to SENDING in a single query
        claimed = db.execute(
            update(Notification)
            .where(
                Notification.status == NotificationStatus.SCHEDULED,
                Notification.scheduled_at <= now
            )
            .values(status=NotificationStatus.SENDING)
            .returning(Notification.id)
        ).all()
        
        db.commit()
        
        # Dispatch only the notifications we claimed
        for (notification_id,) in claimed:
            logger.info(f"Dispatching scheduled notification {notification_id}")
            send_notification_task.delay(notification_id)

        if claimed:
            logger.info(f"Dispatched {len(claimed)} scheduled notifications")
    except Exception as e:
        logger.error(f"Error processing scheduled notifications: {e}")
        db.rollback()
    finally:
        db.close()


def _update_notification_status(db, notification_id: int):
    """Update notification status based on delivery results.
    
    Sets status to:
    - PARTIALLY_SENT: Some deliveries succeeded, some failed
    - SENT: All deliveries succeeded
    - FAILED: All deliveries failed
    """
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        return
    
    total_expected = notification.total_recipients * len(notification.channels)
    total_delivered = notification.sent_count + notification.failed_count
    
    # Only update status if all deliveries are complete
    if total_delivered >= total_expected:
        if notification.failed_count == 0:
            # All succeeded
            notification.status = NotificationStatus.SENT
        elif notification.sent_count == 0:
            # All failed
            notification.status = NotificationStatus.FAILED
        else:
            # Mixed results
            notification.status = NotificationStatus.PARTIALLY_SENT
        
        db.commit()
        logger.info(
            f"Notification {notification_id} status updated to {notification.status}: "
            f"{notification.sent_count} sent, {notification.failed_count} failed out of {total_expected}"
        )


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
