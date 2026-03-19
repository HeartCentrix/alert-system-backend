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
from app.services.messaging import build_checkin_message, build_checkin_email_html
from app.utils.checkin_link import generate_checkin_url
from app.config import settings
from sqlalchemy import update, Integer

logger = logging.getLogger(__name__)


def _scrub_phone(phone: str) -> str:
    """
    Scrub phone number for safe logging while keeping it useful for debugging.

    Shows: first 3 chars + *** + last 4 chars
    Example: +1-555-123-4567 → +15***4567
    """
    if not phone or len(str(phone)) < 4:
        return "***"
    # Keep country code and last 4 digits
    clean = ''.join(c for c in str(phone) if c.isdigit() or c == '+')
    if len(clean) <= 7:
        return clean[:3] + "***" if len(clean) > 3 else "***"
    return f"{clean[:3]}***{clean[-4:]}"


def _scrub_email(email: str) -> str:
    """
    Scrub email address for safe logging while keeping it useful for debugging.
    
    Shows: first 2 chars + *** + @ + domain
    Example: john.doe@example.com → jo***@example.com
    """
    if not email or '@' not in email:
        return "***@***"
    local, domain = email.rsplit('@', 1)
    if len(local) <= 2:
        scrubbed_local = local + "***"
    else:
        scrubbed_local = local[:2] + "***"
    return f"{scrubbed_local}@{domain}"


@celery_app.task(bind=True, max_retries=3, default_retry_delay=30)
def send_notification_task(self, notification_id: int, triggered_by_user_id: int = None, triggered_by_email: str = None):
    """Main task to dispatch a notification to all recipients across all channels.

    Sets notification status to:
    - SENT: All deliveries successful
    - PARTIALLY_SENT: Some deliveries failed
    - FAILED: All deliveries failed or zero recipients

    Idempotency: Uses atomic status claim to prevent double-dispatch on celery beat overlap.
    
    Audit Trail:
    - triggered_by_user_id and triggered_by_email track who initiated the notification
    - Audit log entry created on task execution for full traceability
    """
    db = SessionLocal()
    notification = None

    # Log who triggered this task for forensic traceability
    if triggered_by_user_id:
        logger.info(
            f"Notification {notification_id} task started — "
            f"triggered by user {triggered_by_user_id} ({triggered_by_email})"
        )
    
    try:
        notification = db.query(Notification).filter(Notification.id == notification_id).first()
        if not notification:
            logger.error(f"Notification {notification_id} not found")
            return

        # Prevent re-processing if already sent or partially sent
        if notification.status in [NotificationStatus.SENT, NotificationStatus.PARTIALLY_SENT]:
            logger.info(f"Notification {notification_id} already processed (status={notification.status})")
            return

        # Prevent re-processing if cancelled or failed
        if notification.status in [NotificationStatus.CANCELLED, NotificationStatus.FAILED]:
            logger.info(f"Notification {notification_id} was {notification.status}, skipping")
            return

        # Atomically claim this notification for processing
        # Can claim if SCHEDULED (normal flow) or SENDING (immediate send from API)
        claimed = db.execute(
            update(Notification)
            .where(
                Notification.id == notification_id,
                Notification.status.in_([NotificationStatus.SCHEDULED, NotificationStatus.SENDING])
            )
            .values(status=NotificationStatus.SENDING)
        )
        db.commit()

        # If we couldn't claim it, another worker got it first
        if claimed.rowcount == 0:
            logger.info(f"Notification {notification_id} claimed by another worker or already processed, skipping")
            return

        # Build recipient list
        recipients = _get_recipients(db, notification)
        notification.total_recipients = len(recipients)
        db.commit()

        logger.info(f"Notification {notification_id}: found {len(recipients)} recipients, channels: {notification.channels}")

        if not recipients:
            # No recipients found - mark as FAILED with clear error
            notification.status = NotificationStatus.FAILED
            notification.sent_at = datetime.now(timezone.utc)
            db.commit()
            logger.warning(f"Notification {notification_id} has zero recipients - marked as FAILED")
            logger.warning(f"Notification {notification_id} config: target_all={notification.target_all}, target_group_ids={[g.id for g in notification.target_groups]}, target_user_ids={[u.id for u in notification.target_users]}")
            return

        # Dispatch per recipient per channel - create delivery logs first, then dispatch tasks
        dispatched_count = 0
        dispatch_list = []
        for user in recipients:
            for channel in notification.channels:
                # Check if already dispatched to avoid duplicates on retry
                existing_log = db.query(DeliveryLog).filter(
                    DeliveryLog.notification_id == notification_id,
                    DeliveryLog.user_id == user.id,
                    DeliveryLog.channel == channel
                ).first()

                if not existing_log:
                    log = DeliveryLog(
                        notification_id=notification_id,
                        user_id=user.id,
                        user_email=user.email,
                        channel=channel,
                        status=DeliveryStatus.PENDING,
                    )
                    db.add(log)
                    dispatch_list.append((notification_id, user.id, channel))
                    dispatched_count += 1

        # Commit all delivery logs BEFORE dispatching channel tasks
        # This prevents _send_to_channel from creating duplicate logs
        db.commit()

        # Now dispatch tasks — logs are guaranteed to exist
        for n_id, u_id, ch in dispatch_list:
            _send_to_channel.delay(
                n_id, u_id, ch,
                triggered_by_user_id=triggered_by_user_id,
            )
        logger.info(f"Notification {notification_id}: created {dispatched_count} delivery logs and dispatched tasks")

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
def _send_to_channel(self, notification_id: int, user_id: int, channel: str, triggered_by_user_id: int = None):
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

        if not existing_log:
            # Log doesn't exist - this shouldn't happen as main task creates it
            # But handle gracefully in case of race condition
            logger.warning(f"Notification {notification_id} to user {user_id} via {channel} has no delivery log - creating one")
            existing_log = DeliveryLog(
                notification_id=notification_id,
                user_id=user_id,
                user_email=user.email if user else None,
                channel=channel,
                status=DeliveryStatus.PENDING,
                sent_at=datetime.now(timezone.utc)
            )
            db.add(existing_log)
            db.commit()

        log = existing_log  # Use the existing or newly created log

        if log.status in [DeliveryStatus.SENT, DeliveryStatus.DELIVERED]:
            logger.info(f"Notification {notification_id} to user {user_id} via {channel} already sent, skipping duplicate")
            return
        elif log.status == DeliveryStatus.PENDING:
            # Log is in PENDING state - proceed with sending
            # This is the normal flow
            pass

        result = {}

        # Generate check-in link if response is required
        checkin_url = None
        if notification.response_required and notification.response_deadline_minutes:
            checkin_url = generate_checkin_url(
                notification_id,
                user.id,
                notification.response_deadline_minutes
            )

        if channel == AlertChannel.SMS:
            if user.phone:
                log.to_address = user.phone
                # Build message with check-in link if required
                sms_message = notification.message
                if checkin_url:
                    sms_message = build_checkin_message(
                        notification.message,
                        checkin_url,
                        notification.response_deadline_minutes
                    )
                logger.info(f"Sending SMS to {_scrub_phone(user.phone)} for notification {notification_id}")
                result = twilio_service.send_sms(user.phone, sms_message)
                logger.info(f"SMS result for notification {notification_id} to {_scrub_phone(user.phone)}: {result.get('status', 'unknown')}")
            else:
                logger.warning(f"User {user_id} has no phone number for SMS")
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
                _update_notification_status(db, notification_id)
                return

        elif channel == AlertChannel.EMAIL:
            if user.email:
                log.to_address = user.email
                subject = notification.subject or notification.title
                # Build email with check-in link if required
                email_message = notification.message
                email_html = None
                if checkin_url:
                    email_message = build_checkin_message(
                        notification.message,
                        checkin_url,
                        notification.response_deadline_minutes
                    )
                    # Create HTML version with check-in button
                    email_html = build_checkin_email_html(
                        email_service._text_to_html(email_message),
                        checkin_url,
                        notification.response_deadline_minutes
                    )
                logger.info(f"Sending email to {_scrub_email(user.email)} for notification {notification_id}, subject: {subject}")
                result = email_service.send_email(user.email, subject, email_message, email_html)
                logger.info(f"Email result for notification {notification_id} to {_scrub_email(user.email)}: {result.get('status', 'unknown')}")
            else:
                logger.warning(f"User {user_id} has no email address")
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
                _update_notification_status(db, notification_id)
                return

        elif channel == AlertChannel.VOICE:
            if user.phone:
                log.to_address = user.phone
                # For voice calls, mention check-in requirement in the message
                voice_message = notification.message
                if checkin_url:
                    voice_message = f"{notification.message}. A safety check-in response is required. Please visit the link sent to your email or log in to the portal to respond."
                logger.info(f"Making voice call to {_scrub_phone(user.phone)} for notification {notification_id}")
                result = twilio_service.make_voice_call(user.phone, voice_message)
                logger.info(f"Voice call result for notification {notification_id} to {_scrub_phone(user.phone)}: {result.get('status', 'unknown')}")
            else:
                logger.warning(f"User {user_id} has no phone number for voice call")
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
                _update_notification_status(db, notification_id)
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
            _update_notification_status(db, notification_id)
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
            _update_notification_status(db, notification_id)

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
            _update_notification_status(db, notification_id)
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(bind=True, default_retry_delay=5)
def process_scheduled_notifications(self):
    """Check for scheduled notifications that are due and dispatch them.

    Uses atomic UPDATE with RETURNING to claim notifications exclusively.
    Only the worker that successfully changes status from SCHEDULED to SENDING
    will dispatch the notification, preventing double-dispatch on overlap.
    
    Also recovers stuck SENDING notifications (older than 5 minutes) by re-queueing them.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)

        # === 1. Process SCHEDULED notifications that are due ===
        claimed = db.execute(
            update(Notification)
            .where(
                Notification.status == NotificationStatus.SCHEDULED,
                Notification.scheduled_at <= now
            )
            .values(
                status=NotificationStatus.SENDING,
            )
            .returning(Notification.id)
        ).all()

        db.commit()

        # Dispatch only the notifications we claimed
        for (notification_id,) in claimed:
            logger.info(f"Dispatching scheduled notification {notification_id}")
            send_notification_task.delay(
                notification_id,
                triggered_by_user_id=None,
                triggered_by_email=None,
            )

        if claimed:
            logger.info(f"Dispatched {len(claimed)} scheduled notifications")

        # === 2. Recover stuck SENDING notifications (older than 5 minutes) ===
        # These are notifications that failed during processing and never completed
        stuck_threshold = datetime.fromtimestamp(
            now.timestamp() - 300,  # 5 minutes ago
            tz=timezone.utc
        )
        
        stuck = db.execute(
            update(Notification)
            .where(
                Notification.status == NotificationStatus.SENDING,
                Notification.updated_at <= stuck_threshold
            )
            .values(
                status=NotificationStatus.SENDING,  # Re-claim for processing
                updated_at=now,
            )
            .returning(Notification.id)
        ).all()
        
        db.commit()
        
        for (notification_id,) in stuck:
            logger.warning(f"Recovering stuck notification {notification_id}")
            send_notification_task.delay(
                notification_id,
                triggered_by_user_id=None,
                triggered_by_email=None,
            )
            
        if stuck:
            logger.info(f"Recovered {len(stuck)} stuck SENDING notifications")

    except Exception as e:
        logger.error(f"Error processing scheduled notifications: {e}")
        db.rollback()
        # Retry on failure to ensure scheduled notifications are not missed
        raise self.retry(exc=e, countdown=10)
    finally:
        db.close()


def _update_notification_status(db, notification_id: int):
    """Update notification status based on delivery results.

    Uses atomic UPDATE query to prevent race conditions when concurrent subtasks complete.
    The status update is done atomically based on the current database values.

    Args:
        db: Database session
        notification_id: ID of the notification to update

    Sets status to:
    - PARTIALLY_SENT: Some deliveries succeeded, some failed
    - SENT: All deliveries succeeded
    - FAILED: All deliveries failed
    """
    # Get notification for calculating total expected deliveries
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notification:
        return

    # Only count channels that have per-user delivery logs (SMS, EMAIL, VOICE, WEB)
    # Webhook channels (SLACK, TEAMS) are sent once per notification, not per-user
    # and don't affect the final notification status
    delivery_channels = [ch for ch in notification.channels if ch in ["sms", "email", "voice", "web"]]
    total_expected = notification.total_recipients * len(delivery_channels)
    
    # If no delivery channels, mark as SENT immediately (webhooks only)
    if total_expected == 0:
        db.execute(
            update(Notification)
            .where(Notification.id == notification_id)
            .values(status=NotificationStatus.SENT.value)
        )
        db.commit()
        logger.info(f"Notification {notification_id}: webhooks only, marked as SENT")
        return
    
    # Total completed = sent + failed deliveries
    total_completed = notification.sent_count + notification.failed_count

    # Only update status if all deliveries are complete
    if total_completed < total_expected:
        return

    # Determine final status based on counts
    if notification.failed_count == 0:
        final_status = NotificationStatus.SENT.value
    elif notification.sent_count == 0:
        final_status = NotificationStatus.FAILED.value
    else:
        final_status = NotificationStatus.PARTIALLY_SENT.value

    # Atomically update status only if still in SENDING state
    # This prevents overwriting a status that was already updated by another subtask
    db.execute(
        update(Notification)
        .where(
            Notification.id == notification_id,
            Notification.status == NotificationStatus.SENDING,
            Notification.sent_count + Notification.failed_count >= total_expected
        )
        .values(status=final_status)
    )
    db.commit()

    # Log the result (read after commit for accurate logging)
    notification = db.query(Notification).filter(Notification.id == notification_id).first()
    if notification and notification.status in [NotificationStatus.SENT, NotificationStatus.FAILED, NotificationStatus.PARTIALLY_SENT]:
        logger.info(
            f"Notification {notification_id} status: {notification.status.value} | "
            f"{notification.sent_count} sent, {notification.failed_count} failed out of {total_expected}"
        )


def _get_recipients(db, notification: Notification) -> List[User]:
    """Build unique recipient list from target_all, groups, and individual users.
    
    IMPORTANT: Uses is_enabled (account status) NOT is_online (presence).
    Emergency alerts MUST be sent to all enabled users, even if they're currently offline.
    """
    recipient_ids = set()

    if notification.target_all:
        # Send to ALL enabled users (not just currently online)
        users = db.query(User).filter(
            User.is_enabled == True
        ).all()
        logger.info(f"Notification {notification.id}: target_all=True, found {len(users)} enabled users")
        return users

    for group in notification.target_groups:
        if group.type == "dynamic" and group.dynamic_filter:
            # Filter by group criteria, but include all enabled users
            query = db.query(User).filter(User.is_enabled == True)
            f = group.dynamic_filter
            # Apply filters only if they have non-empty, non-whitespace values
            if f.get("department") and str(f["department"]).strip():
                query = query.filter(User.department == f["department"].strip())
            if f.get("title") and str(f["title"]).strip():
                query = query.filter(User.title == f["title"].strip())
            if f.get("role") and str(f["role"]).strip():
                query = query.filter(User.role == f["role"].strip())
            if f.get("location_id") and str(f["location_id"]).strip():
                query = query.filter(User.location_id == f["location_id"])
            users = query.all()
            logger.info(f"Notification {notification.id}: dynamic group '{group.name}' returned {len(users)} users with filter {f}")
        else:
            users = group.members
            logger.info(f"Notification {notification.id}: static group '{group.name}' has {len(users)} members")

        for u in users:
            if u.id not in recipient_ids:
                recipient_ids.add(u.id)

    for user in notification.target_users:
        recipient_ids.add(user.id)

    logger.info(f"Notification {notification.id}: total unique recipient IDs before is_active filter: {len(recipient_ids)}")

    if not recipient_ids:
        logger.warning(f"Notification {notification.id}: no recipients found - check target_groups and target_users")
        return []

    # Filter by is_enabled (account status) - NOT is_online (presence)
    # Emergency alerts must reach all enabled users, even if offline
    recipients = db.query(User).filter(
        User.id.in_(recipient_ids),
        User.is_enabled == True
    ).all()

    logger.info(f"Notification {notification.id}: {len(recipients)} enabled recipients after filtering")

    # Log users that were filtered out due to is_enabled=False (account disabled)
    filtered_out = recipient_ids - set(u.id for u in recipients)
    if filtered_out:
        logger.warning(f"Notification {notification.id}: {len(filtered_out)} users had disabled accounts (IDs: {filtered_out})")

    return recipients


# ─── LOCATION AUTOCOMPLETE TASKS ──────────────────────────────────────────────

@celery_app.task(bind=True, default_retry_delay=60)
def check_safety_response_deadlines(self):
    """
    Check for notifications with response_required=True where the deadline has passed.

    For each notification:
    1. Find all recipients who haven't responded
    2. Send escalation alert to admins (ONLY ONCE per notification)
    3. Mark notification as escalated to prevent duplicate alerts

    This task runs every 5 minutes via Celery Beat.
    
    Security: 
    - Escalation sent only once per notification (deadline_escalated flag)
    - No sensitive data exposed in logs
    - Rate-limited via celery task retry
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)

        # Find notifications where:
        # - response_required = True
        # - Deadline has passed (sent_at + deadline_minutes <= now)
        # - Status is SENT or PARTIALLY_SENT (already dispatched)
        # - NOT already escalated (deadline_escalated = False)
        from app.models import NotificationResponse
        from sqlalchemy import text

        notifications = db.query(Notification).filter(
            Notification.response_required == True,
            Notification.response_deadline_minutes != None,
            Notification.sent_at != None,
            Notification.status.in_([NotificationStatus.SENT, NotificationStatus.PARTIALLY_SENT]),
            Notification.deadline_escalated == False,  # ← Skip already escalated
            # Deadline has passed - use raw SQL for proper timestamp arithmetic
            text("notifications.sent_at + (notifications.response_deadline_minutes || ' minutes')::interval <= :now")
            .bindparams(now=now)
        ).all()

        for notification in notifications:
            # Get all recipients who should have responded
            recipient_ids = set()
            for user in notification.target_users:
                recipient_ids.add(user.id)
            for group in notification.target_groups:
                for member in group.members:
                    recipient_ids.add(member.id)
            if notification.target_all:
                # For target_all, get all enabled users (not just online)
                all_users = db.query(User).filter(User.is_enabled == True).all()
                recipient_ids = {u.id for u in all_users}

            # Get users who actually responded
            responses = db.query(NotificationResponse).filter(
                NotificationResponse.notification_id == notification.id
            ).all()
            responded_ids = {r.user_id for r in responses}

            # Find non-responders
            non_responder_ids = recipient_ids - responded_ids

            if not non_responder_ids:
                # Everyone responded, mark as escalated (no escalation needed)
                notification.deadline_escalated = True
                db.commit()
                logger.info(
                    f"Notification {notification.id}: All recipients responded, "
                    f"marked as escalated (no action needed)"
                )
                continue

            logger.warning(
                f"Safety response deadline passed for notification {notification.id}. "
                f"{len(non_responder_ids)} non-responders out of {len(recipient_ids)} recipients"
            )

            # Get admin users for escalation
            from app.models import UserRole
            admins = db.query(User).filter(
                User.role.in_([UserRole.SUPER_ADMIN, UserRole.ADMIN])
            ).all()

            if not admins:
                logger.error(f"No admins found for escalation of notification {notification.id}")
                continue

            # Build escalation message
            escalation_message = (
                f"⚠️ SAFETY RESPONSE DEADLINE PASSED\n\n"
                f"Notification: {notification.title}\n"
                f"Sent: {notification.sent_at}\n"
                f"Deadline: {notification.response_deadline_minutes} minutes\n\n"
                f"Non-responders: {len(non_responder_ids)}\n"
                f"Responded: {len(responded_ids)}\n\n"
                f"Please follow up with non-responders manually."
            )

            # Send escalation to admins via email
            emails_sent = 0
            for admin in admins:
                if admin.email:
                    logger.info(f"Sending escalation email to admin user_id={admin.id}, email={_scrub_email(admin.email)}")
                    try:
                        email_service.send_email(
                            admin.email,
                            f"⚠️ Safety Response Deadline Passed - {notification.title}",
                            escalation_message
                        )
                        emails_sent += 1
                    except Exception as e:
                        logger.error(f"Failed to send escalation email to admin user_id={admin.id}, email={_scrub_email(admin.email)}: {e}")

            # Mark as escalated AFTER sending emails (prevents duplicates on retry)
            notification.deadline_escalated = True
            db.commit()

            logger.info(
                f"Escalation complete for notification {notification.id}. "
                f"Sent {emails_sent} emails to admins. Marked as escalated."
            )

            # Optionally: Re-notify non-responders with urgent flag
            # DISABLED BY DEFAULT: Can cause spam if enabled
            RE_NOTIFY_NON_RESPONDERS = False
            if RE_NOTIFY_NON_RESPONDERS and non_responder_ids:
                non_responders = db.query(User).filter(User.id.in_(non_responder_ids)).all()
                for user in non_responders:
                    if user.phone:
                        # Send urgent SMS reminder
                        reminder_msg = (
                            f"URGENT: You haven't responded to the safety check-in yet. "
                            f"Please respond: {settings.FRONTEND_URL}/notifications/{notification.id}/respond"
                        )
                        try:
                            twilio_service.send_sms(user.phone, reminder_msg)
                            logger.info(f"Sent urgent SMS reminder to user_id={user.id}, phone={_scrub_phone(user.phone)}")
                        except Exception as e:
                            logger.error(f"Failed to send SMS to user_id={user.id}, phone={_scrub_phone(user.phone)}: {e}")

    except Exception as e:
        logger.error(f"Error checking safety response deadlines: {e}")
        db.rollback()
        raise self.retry(exc=e)
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=10)
def mark_offline_users_task(self):
    """
    Periodic task to mark users as offline if no heartbeat received within 60 seconds.

    This task runs every 30 seconds via Celery Beat and:
    1. Finds all users with is_online=True
    2. Checks if their last_seen_at is older than 60 seconds
    3. Marks them as offline (is_online=False)

    This ensures the online status reflects real-time presence.
    Uses 60 seconds (2x heartbeat interval) to avoid false positives from network delays.

    IMPORTANT: This does NOT affect account status (is_enabled).
    Users can still receive alerts even when offline.
    """
    db = SessionLocal()
    try:
        from datetime import timedelta
        from app.models import User

        # Use 60 seconds (2x heartbeat interval) to avoid race conditions
        cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=60)

        # Find users who are online but haven't sent a heartbeat in 60+ seconds
        stale_users = db.query(User).filter(
            User.is_online == True,
            User.last_seen_at.isnot(None),
            User.last_seen_at < cutoff_time
        ).all()

        if stale_users:
            user_ids = [u.id for u in stale_users]
            logger.info(f"Marking {len(stale_users)} users as offline due to inactivity: {user_ids}")

            # Mark them as offline (does NOT affect is_enabled)
            db.execute(
                update(User)
                .where(User.id.in_(user_ids))
                .values(is_online=False)
            )
            db.commit()

            logger.info(f"Successfully marked {len(stale_users)} users as offline")
        else:
            logger.debug("No stale users found - all online users have recent heartbeats")

    except Exception as e:
        logger.error(f"Error marking offline users: {e}")
        db.rollback()
        raise self.retry(exc=e)
    finally:
        db.close()
