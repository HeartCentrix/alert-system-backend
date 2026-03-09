import logging
import httpx
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import (
    Notification, NotificationStatus, DeliveryLog, DeliveryStatus,
    AlertChannel, User
)
from app.services.messaging import twilio_service, email_service, webhook_service
from app.config import settings
from sqlalchemy import update

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def send_notification_task(self, notification_id: int):
    """Main task to dispatch a notification to all recipients across all channels.

    Sets notification status to:
    - SENT: All deliveries successful
    - PARTIALLY_SENT: Some deliveries failed
    - FAILED: All deliveries failed or zero recipients
    
    Idempotency: Uses atomic status claim to prevent double-dispatch on celery beat overlap.
    """
    db = SessionLocal()
    notification = None
    try:
        notification = db.query(Notification).filter(Notification.id == notification_id).first()
        if not notification:
            logger.error(f"Notification {notification_id} not found")
            return

        # Prevent re-processing if already sent or partially sent
        if notification.status in [NotificationStatus.SENT, NotificationStatus.PARTIALLY_SENT]:
            logger.info(f"Notification {notification_id} already processed (status={notification.status})")
            return
        
        # Idempotency check: If already SENDING, another worker claimed it
        # Skip to prevent double-dispatch on celery beat overlap
        if notification.status == NotificationStatus.SENDING:
            logger.info(f"Notification {notification_id} already being processed (status=SENDING)")
            return

        # Atomically claim this notification for processing
        # Uses optimistic locking: only succeed if status is still SCHEDULED
        claimed = db.execute(
            update(Notification)
            .where(
                Notification.id == notification_id,
                Notification.status == NotificationStatus.SCHEDULED
            )
            .values(status=NotificationStatus.SENDING)
        )
        db.commit()
        
        # If we couldn't claim it, another worker got it first
        if claimed.rowcount == 0:
            logger.info(f"Notification {notification_id} claimed by another worker, skipping")
            return

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
    """Send notification to a single user via a single channel.
    
    Creates a DeliveryLog entry for every attempt to track delivery status.
    Exceptions are logged and the delivery is marked as FAILED.
    
    Idempotency: Checks for existing delivery log (including PENDING) to prevent
    duplicate sends when task_acks_late=True causes task re-queue on worker crash.
    """
    db = SessionLocal()
    log = None  # Initialize early to avoid UnboundLocalError in exception handler
    
    try:
        notification = db.query(Notification).filter(Notification.id == notification_id).first()
        user = db.query(User).filter(User.id == user_id).first()

        if not notification or not user:
            logger.warning(f"Notification {notification_id} or user {user_id} not found")
            return

        # Idempotency check: skip if already processed OR currently being processed
        # This prevents duplicates when:
        # 1. Worker crashes after sending but before ack (task re-queued)
        # 2. Worker crashes after creating PENDING log but before sending
        existing_log = db.query(DeliveryLog).filter(
            DeliveryLog.notification_id == notification_id,
            DeliveryLog.user_id == user_id,
            DeliveryLog.channel == channel
        ).first()

        if existing_log:
            if existing_log.status in [DeliveryStatus.SENT, DeliveryStatus.DELIVERED]:
                logger.info(f"Notification {notification_id} to user {user_id} via {channel} already sent, skipping duplicate")
                return
            elif existing_log.status == DeliveryStatus.PENDING:
                # Log exists in PENDING state - previous worker likely crashed after sending
                # Don't retry to avoid duplicate - mark as SENT to prevent future retries
                logger.warning(
                    f"Notification {notification_id} to user {user_id} via {channel} has PENDING log "
                    f"(previous worker may have crashed). Marking as SENT to avoid duplicate."
                )
                existing_log.status = DeliveryStatus.SENT
                existing_log.sent_at = datetime.now(timezone.utc)
                db.commit()
                # Atomically increment sent count
                db.execute(
                    update(Notification)
                    .where(Notification.id == notification_id)
                    .values(sent_count=Notification.sent_count + 1)
                )
                db.commit()
                _update_notification_status(db, notification_id, total_channels)
                return

        # Cache total_channels for status update (avoids extra query later)
        total_channels = len(notification.channels)

        # Create delivery log entry at the start to track this attempt
        user = db.query(User).filter(User.id == user_id).first()
        log = DeliveryLog(
            notification_id=notification_id,
            user_id=user_id,
            user_email=user.email if user else None,
            channel=channel,
            status=DeliveryStatus.PENDING,
            sent_at=datetime.now(timezone.utc)
        )
        db.add(log)
        db.commit()

        result = {}

        if channel == AlertChannel.SMS:
            if user.phone:
                log.to_address = user.phone
                result = twilio_service.send_sms(user.phone, notification.message)
            else:
                log.status = DeliveryStatus.FAILED
                log.error_message = "No phone number"
                db.commit()
                # Atomic increment and status update
                db.execute(
                    update(Notification)
                    .where(Notification.id == notification_id)
                    .values(failed_count=Notification.failed_count + 1)
                )
                db.commit()
                _update_notification_status(db, notification_id, total_channels)
                return

        elif channel == AlertChannel.EMAIL:
            if user.email:
                log.to_address = user.email
                subject = notification.subject or notification.title
                result = email_service.send_email(user.email, subject, notification.message)
            else:
                log.status = DeliveryStatus.FAILED
                log.error_message = "No email address"
                db.commit()
                # Atomic increment and status update
                db.execute(
                    update(Notification)
                    .where(Notification.id == notification_id)
                    .values(failed_count=Notification.failed_count + 1)
                )
                db.commit()
                _update_notification_status(db, notification_id, total_channels)
                return

        elif channel == AlertChannel.VOICE:
            if user.phone:
                log.to_address = user.phone
                result = twilio_service.make_voice_call(user.phone, notification.message)
            else:
                log.status = DeliveryStatus.FAILED
                log.error_message = "No phone number for voice call"
                db.commit()
                # Atomic increment and status update
                db.execute(
                    update(Notification)
                    .where(Notification.id == notification_id)
                    .values(failed_count=Notification.failed_count + 1)
                )
                db.commit()
                _update_notification_status(db, notification_id, total_channels)
                return

        # Update log based on result
        if result.get("error"):
            log.status = DeliveryStatus.FAILED
            log.error_message = result["error"]
            db.commit()
            # Atomic increment to avoid race condition
            # Uses SQL-level increment: failed_count = failed_count + 1
            db.execute(
                update(Notification)
                .where(Notification.id == notification_id)
                .values(failed_count=Notification.failed_count + 1)
            )
            db.commit()
            # Update notification status based on delivery results
            # This uses atomic UPDATE with WHERE clause to prevent race conditions
            _update_notification_status(db, notification_id, total_channels)
        else:
            log.status = DeliveryStatus.SENT
            log.external_id = result.get("sid") or result.get("message_id")
            db.commit()
            # Atomic increment to avoid race condition
            # Uses SQL-level increment: sent_count = sent_count + 1
            db.execute(
                update(Notification)
                .where(Notification.id == notification_id)
                .values(sent_count=Notification.sent_count + 1)
            )
            db.commit()
            # Update notification status based on delivery results
            # This uses atomic UPDATE with WHERE clause to prevent race conditions
            _update_notification_status(db, notification_id, total_channels)

    except Exception as e:
        logger.error(f"Error sending to user {user_id} via {channel}: {e}")
        # Mark delivery as FAILED in the log (if log was created)
        if log:
            log.status = DeliveryStatus.FAILED
            log.error_message = str(e)
            db.add(log)
            db.commit()
            # Atomic increment for failed count
            db.execute(
                update(Notification)
                .where(Notification.id == notification_id)
                .values(failed_count=Notification.failed_count + 1)
            )
            db.commit()
            _update_notification_status(db, notification_id, total_channels)
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(bind=True, default_retry_delay=5)
def process_scheduled_notifications(self):
    """Check for scheduled notifications that are due and dispatch them.
    
    Uses atomic UPDATE with RETURNING to claim notifications exclusively.
    Only the worker that successfully changes status from SCHEDULED to SENDING
    will dispatch the notification, preventing double-dispatch on overlap.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)

        # Atomically claim due notifications to prevent duplicate dispatch
        # Uses FOR UPDATE-style locking via atomic status change
        # Only this worker will get these IDs in the RETURNING clause
        claimed = db.execute(
            update(Notification)
            .where(
                Notification.status == NotificationStatus.SCHEDULED,
                Notification.scheduled_at <= now
            )
            .values(
                status=NotificationStatus.SENDING,
                # Mark as claimed by this execution (idempotency safeguard)
            )
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
        # Retry on failure to ensure scheduled notifications are not missed
        raise self.retry(exc=e, countdown=10)
    finally:
        db.close()


def _update_notification_status(db, notification_id: int, total_channels: int):
    """Update notification status based on delivery results.

    Uses atomic UPDATE query to prevent race conditions when concurrent subtasks complete.
    The status update is done atomically based on the current database values.
    
    Args:
        db: Database session
        notification_id: ID of the notification to update
        total_channels: Number of channels for this notification (prevents extra query)
    
    Sets status to:
    - PARTIALLY_SENT: Some deliveries succeeded, some failed
    - SENT: All deliveries succeeded  
    - FAILED: All deliveries failed
    """
    # Get total recipients for calculating total expected deliveries
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        return
    
    total_expected = notification.total_recipients * total_channels
    
    # Atomically update status only when all deliveries are complete
    # Uses SQL-level comparison to ensure atomicity - only ONE concurrent subtask
    # will successfully update the status (the one that completes last)
    from sqlalchemy import case
    
    db.execute(
        update(Notification)
        .where(
            Notification.id == notification_id,
            # Only update if all deliveries are complete
            Notification.sent_count + Notification.failed_count >= total_expected
        )
        .values({
            "status": case(
                (Notification.failed_count == 0, NotificationStatus.SENT.value),
                (Notification.sent_count == 0, NotificationStatus.FAILED.value),
                else_=NotificationStatus.PARTIALLY_SENT.value
            )
        })
    )
    db.commit()
    
    # Log the result (read after commit for accurate logging)
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if notification and notification.status in [NotificationStatus.SENT, NotificationStatus.FAILED, NotificationStatus.PARTIALLY_SENT]:
        total_delivered = notification.sent_count + notification.failed_count
        logger.info(
            f"Notification {notification_id} status: {notification.status.value} | "
            f"{notification.sent_count} sent, {notification.failed_count} failed out of {total_expected}"
        )


def _get_recipients(db, notification: Notification) -> List[User]:
    """Build unique recipient list from target_all, groups, and individual users."""
    recipient_ids = set()

    if notification.target_all:
        users = db.query(User).filter(
            User.is_active == True
        ).all()
        return users

    for group in notification.target_groups:
        if group.type == "dynamic" and group.dynamic_filter:
            query = db.query(User).filter(User.is_active == True)
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
        User.is_active == True
    ).all()


# ─── LOCATION AUTOCOMPLETE TASKS ──────────────────────────────────────────────

@celery_app.task(bind=True, max_retries=2, default_retry_delay=5)
def fetch_location_autocomplete_task(
    self,
    query: str,
    limit: int = 10,
    countrycodes: Optional[str] = None,
    viewbox: Optional[str] = None,
    bounded: bool = False,
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch location autocomplete results from LocationIQ API.
    
    This task is called when cache misses occur. Results should be cached
    in Redis after successful fetch.
    
    Args:
        query: Search query (already normalized)
        limit: Max results (1-20)
        countrycodes: Comma-separated country codes (e.g., 'us,ca')
        viewbox: Bounding box for biasing (x1,y1,x2,y2)
        bounded: Restrict results to viewbox
        
    Returns:
        List of location results or None on failure
    """
    if not settings.LOCATIONIQ_API_KEY:
        logger.error("LocationIQ API key not configured")
        return None
    
    url = f"{settings.LOCATIONIQ_BASE_URL}/autocomplete"
    params = {
        "key": settings.LOCATIONIQ_API_KEY,
        "q": query,
        "limit": min(limit, 20),  # Enforce max limit
        "format": "json",
    }
    
    if countrycodes:
        params["countrycodes"] = countrycodes
    
    if viewbox:
        params["viewbox"] = viewbox
        params["bounded"] = "1" if bounded else "0"
    
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(url, params=params)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 5))
                logger.warning(f"LocationIQ rate limited. Retrying after {retry_after}s")
                raise self.retry(countdown=retry_after)
            
            response.raise_for_status()
            data = response.json()
            
            # Normalize results
            results = []
            for item in data:
                display_name = item.get("display_name", "")
                parts = display_name.split(", ")
                
                results.append({
                    "place_id": str(item.get("place_id", "")),
                    "display_name": display_name,
                    "display_place": parts[0] if parts else display_name,
                    "display_address": ", ".join(parts[1:]) if len(parts) > 1 else "",
                    "lat": float(item.get("lat", 0)),
                    "lon": float(item.get("lon", 0)),
                    "address": {
                        "name": item.get("address", {}).get("name", ""),
                        "road": item.get("address", {}).get("road", ""),
                        "city": item.get("address", {}).get("city", 
                                item.get("address", {}).get("town", 
                                item.get("address", {}).get("village", ""))),
                        "state": item.get("address", {}).get("state", ""),
                        "postcode": item.get("address", {}).get("postcode", ""),
                        "country": item.get("address", {}).get("country", ""),
                        "country_code": item.get("address", {}).get("country_code", ""),
                    },
                    "type": item.get("type", ""),
                    "importance": item.get("importance", 0),
                })
            
            logger.info(f"Fetched {len(results)} location results for query: {query}")
            return results
            
    except httpx.TimeoutException as e:
        logger.error(f"LocationIQ timeout: {e}")
        raise self.retry(exc=e)
    except httpx.HTTPStatusError as e:
        logger.error(f"LocationIQ HTTP error {e.response.status_code}: {e}")
        if e.response.status_code >= 500:
            raise self.retry(exc=e)
        return None
    except Exception as e:
        logger.error(f"LocationIQ fetch error: {e}")
        raise self.retry(exc=e)
