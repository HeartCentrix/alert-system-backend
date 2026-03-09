"""
Unit Tests for Celery Tasks

Tests cover:
- Notification dispatch task
- Individual channel sending task
- Scheduled notification processing
- Retry logic
- Error handling
- Idempotency
"""
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

from app.tasks import (
    send_notification_task,
    _send_to_channel,
    process_scheduled_notifications,
    _get_recipients,
    _update_notification_status,
)
from app.models import (
    Notification, NotificationStatus, DeliveryLog, DeliveryStatus,
    User, Group, AlertChannel, UserRole
)


# =============================================================================
# NOTIFICATION DISPATCH TASK TESTS
# =============================================================================

class TestSendNotificationTask:
    """Test main notification dispatch task."""

    def test_send_notification_success(
        self, db_session, test_user, mock_celery, mock_all_external_services
    ):
        """Notification should be dispatched successfully."""
        # Create notification
        notification = Notification(
            title="Test Alert",
            message="Test message",
            channels=["sms", "email"],
            target_all=True,
            status=NotificationStatus.DRAFT,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        # Mock the _send_to_channel task
        with patch("app.tasks._send_to_channel") as mock_send:
            mock_send.delay = MagicMock()
            
            # Run task
            send_notification_task(notification.id)
            
            # Notification status should be updated
            db_session.refresh(notification)
            assert notification.status in [
                NotificationStatus.SENDING,
                NotificationStatus.SENT,
                NotificationStatus.PARTIALLY_SENT
            ]

    def test_send_notification_not_found(self, mock_celery):
        """Task should handle non-existent notification."""
        with patch("app.tasks.logger") as mock_logger:
            # Should not raise, just log error
            send_notification_task(99999)
            mock_logger.error.assert_called()

    def test_send_notification_already_sent(
        self, db_session, test_user, mock_celery
    ):
        """Already sent notification should not be re-processed."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            status=NotificationStatus.SENT,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        with patch("app.tasks.logger") as mock_logger:
            send_notification_task(notification.id)
            mock_logger.info.assert_called()
            assert "already processed" in str(mock_logger.info.call_args)

    def test_send_notification_zero_recipients(
        self, db_session, test_user, mock_celery
    ):
        """Notification with zero recipients should fail gracefully."""
        # Deactivate all users first
        db_session.query(User).update({"is_active": False})
        db_session.commit()
        
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            status=NotificationStatus.DRAFT,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        send_notification_task(notification.id)
        
        db_session.refresh(notification)
        assert notification.status == NotificationStatus.FAILED

    def test_send_notification_retry_on_error(
        self, db_session, test_user, mock_celery
    ):
        """Task should retry on error."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            status=NotificationStatus.DRAFT,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        # Simulate error that triggers retry
        with patch("app.tasks._get_recipients") as mock_get:
            mock_get.side_effect = Exception("Database error")
            
            # Task should raise retry exception
            with pytest.raises(Exception):
                send_notification_task(notification.id)

    def test_send_notification_with_groups(
        self, db_session, test_user, test_group, mock_celery, mock_all_external_services
    ):
        """Notification targeted to groups should dispatch correctly."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=False,
            status=NotificationStatus.DRAFT,
            created_by_id=test_user.id,
        )
        notification.target_groups = [test_group]
        db_session.add(notification)
        db_session.commit()
        
        with patch("app.tasks._send_to_channel") as mock_send:
            mock_send.delay = MagicMock()
            send_notification_task(notification.id)
            
            # Should dispatch to group members
            mock_send.delay.assert_called()

    def test_send_notification_scheduled_status(
        self, db_session, test_user, mock_celery
    ):
        """Scheduled notification should have correct status."""
        from datetime import timedelta
        scheduled_time = datetime.now(timezone.utc) + timedelta(hours=1)
        
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            scheduled_at=scheduled_time,
            status=NotificationStatus.DRAFT,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        # Task should handle scheduled notifications
        send_notification_task(notification.id)
        
        db_session.refresh(notification)
        # Status should be updated appropriately


# =============================================================================
# INDIVIDUAL CHANNEL TASK TESTS
# =============================================================================

class TestSendToChannel:
    """Test individual channel sending task."""

    def test_send_sms_channel(
        self, db_session, test_user, test_notification, mock_twilio
    ):
        """SMS channel should send correctly."""
        # Create delivery log
        _send_to_channel(test_notification.id, test_user.id, AlertChannel.SMS)
        
        # Verify SMS was sent
        mock_twilio.send_sms.assert_called()

    def test_send_email_channel(
        self, db_session, test_user, test_notification, mock_email_service
    ):
        """Email channel should send correctly."""
        _send_to_channel(test_notification.id, test_user.id, AlertChannel.EMAIL)
        
        # Verify email was sent
        mock_email_service.send_email.assert_called()

    def test_send_voice_channel(
        self, db_session, test_user, test_notification, mock_twilio
    ):
        """Voice channel should send correctly."""
        _send_to_channel(test_notification.id, test_user.id, AlertChannel.VOICE)
        
        # Verify voice call was made
        mock_twilio.make_voice_call.assert_called()

    def test_send_whatsapp_channel(
        self, db_session, test_user, test_notification, mock_twilio
    ):
        """WhatsApp channel should send correctly."""
        _send_to_channel(test_notification.id, test_user.id, AlertChannel.WHATSAPP)
        
        # Verify WhatsApp was sent
        mock_twilio.send_whatsapp.assert_called()

    def test_send_channel_idempotency(
        self, db_session, test_user, test_notification, mock_twilio
    ):
        """Sending should be idempotent (no duplicates)."""
        # First send
        _send_to_channel(test_notification.id, test_user.id, AlertChannel.SMS)
        
        # Second send should be skipped
        _send_to_channel(test_notification.id, test_user.id, AlertChannel.SMS)
        
        # Should only be called once
        assert mock_twilio.send_sms.call_count == 1

    def test_send_channel_user_no_phone(
        self, db_session, test_notification, mock_twilio
    ):
        """SMS to user without phone should fail gracefully."""
        # Create user without phone
        user = User(
            email="nophone@example.com",
            hashed_password="hashed",
            first_name="No",
            last_name="Phone",
            phone=None,
        )
        db_session.add(user)
        db_session.commit()
        
        _send_to_channel(test_notification.id, user.id, AlertChannel.SMS)
        
        # Should not attempt to send
        mock_twilio.send_sms.assert_not_called()

    def test_send_channel_user_no_email(
        self, db_session, test_notification, mock_email_service
    ):
        """Email to user without email should fail gracefully."""
        user = User(
            email=None,  # No email
            hashed_password="hashed",
            first_name="No",
            last_name="Email",
        )
        db_session.add(user)
        db_session.commit()
        
        _send_to_channel(test_notification.id, user.id, AlertChannel.EMAIL)
        
        # Should not attempt to send
        mock_email_service.send_email.assert_not_called()

    def test_send_channel_retry_on_error(
        self, db_session, test_user, test_notification, mock_twilio
    ):
        """Channel send should retry on error."""
        mock_twilio.send_sms.side_effect = Exception("API Error")
        
        # Should raise retry exception
        with pytest.raises(Exception):
            _send_to_channel(test_notification.id, test_user.id, AlertChannel.SMS)


# =============================================================================
# SCHEDULED NOTIFICATION TESTS
# =============================================================================

class TestProcessScheduledNotifications:
    """Test scheduled notification processing."""

    def test_process_scheduled_due(
        self, db_session, test_user, mock_celery
    ):
        """Due scheduled notifications should be dispatched."""
        from datetime import timedelta
        
        # Create scheduled notification (due 1 hour ago)
        notification = Notification(
            title="Scheduled Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            scheduled_at=datetime.now(timezone.utc) - timedelta(hours=1),
            status=NotificationStatus.SCHEDULED,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        with patch("app.tasks.send_notification_task") as mock_send:
            mock_send.delay = MagicMock()
            process_scheduled_notifications()
            
            # Should dispatch the notification
            mock_send.delay.assert_called()

    def test_process_scheduled_not_due(
        self, db_session, test_user, mock_celery
    ):
        """Future scheduled notifications should not be dispatched."""
        from datetime import timedelta
        
        # Create scheduled notification (due in 1 hour)
        notification = Notification(
            title="Future Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            scheduled_at=datetime.now(timezone.utc) + timedelta(hours=1),
            status=NotificationStatus.SCHEDULED,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        with patch("app.tasks.send_notification_task") as mock_send:
            mock_send.delay = MagicMock()
            process_scheduled_notifications()
            
            # Should not dispatch
            mock_send.delay.assert_not_called()

    def test_process_scheduled_already_sent(
        self, db_session, test_user, mock_celery
    ):
        """Already sent notifications should not be re-dispatched."""
        from datetime import timedelta
        
        notification = Notification(
            title="Already Sent",
            message="Test",
            channels=["sms"],
            target_all=True,
            scheduled_at=datetime.now(timezone.utc) - timedelta(hours=1),
            status=NotificationStatus.SENT,  # Already sent
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        with patch("app.tasks.send_notification_task") as mock_send:
            mock_send.delay = MagicMock()
            process_scheduled_notifications()
            
            mock_send.delay.assert_not_called()


# =============================================================================
# RECIPIENT BUILDING TESTS
# =============================================================================

class TestGetRecipients:
    """Test recipient list building."""

    def test_get_recipients_target_all(
        self, db_session, test_user
    ):
        """Target all should return all active users."""
        # Create additional users
        user2 = User(
            email="user2@example.com",
            hashed_password="hashed",
            first_name="User",
            last_name="Two",
            is_active=True,
        )
        db_session.add(user2)
        db_session.commit()
        
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        recipients = _get_recipients(db_session, notification)
        
        # Should include all active users
        assert len(recipients) >= 2
        assert test_user in recipients

    def test_get_recipients_excludes_inactive(
        self, db_session, test_user, inactive_user
    ):
        """Inactive users should be excluded."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=True,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        recipients = _get_recipients(db_session, notification)
        
        assert inactive_user not in recipients

    def test_get_recipients_target_groups(
        self, db_session, test_user, test_group
    ):
        """Target groups should return group members."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=False,
            created_by_id=test_user.id,
        )
        notification.target_groups = [test_group]
        db_session.add(notification)
        db_session.commit()
        
        recipients = _get_recipients(db_session, notification)
        
        assert test_user in recipients  # test_user is in test_group

    def test_get_recipients_dynamic_groups(
        self, db_session, test_user
    ):
        """Dynamic groups should filter by criteria."""
        # Create group with dynamic filter
        group = Group(
            name="Dynamic Group",
            type="dynamic",
            dynamic_filter={"department": "Engineering"},
        )
        db_session.add(group)
        db_session.commit()
        
        # Create user matching filter
        eng_user = User(
            email="eng@example.com",
            hashed_password="hashed",
            first_name="Eng",
            last_name="User",
            department="Engineering",
            is_active=True,
        )
        db_session.add(eng_user)
        db_session.commit()
        
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=False,
            created_by_id=test_user.id,
        )
        notification.target_groups = [group]
        db_session.add(notification)
        db_session.commit()
        
        recipients = _get_recipients(db_session, notification)
        
        assert eng_user in recipients

    def test_get_recipients_target_users(
        self, db_session, test_user
    ):
        """Target specific users should work."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=False,
            created_by_id=test_user.id,
        )
        notification.target_users = [test_user]
        db_session.add(notification)
        db_session.commit()
        
        recipients = _get_recipients(db_session, notification)
        
        assert test_user in recipients
        assert len(recipients) == 1


# =============================================================================
# STATUS UPDATE TESTS
# =============================================================================

class TestUpdateNotificationStatus:
    """Test notification status updates."""

    def test_update_status_all_sent(
        self, db_session, test_user
    ):
        """Status should be SENT when all deliveries succeed."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=False,
            total_recipients=1,
            sent_count=1,
            failed_count=0,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        _update_notification_status(db_session, notification.id)
        
        db_session.refresh(notification)
        assert notification.status == NotificationStatus.SENT

    def test_update_status_all_failed(
        self, db_session, test_user
    ):
        """Status should be FAILED when all deliveries fail."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=False,
            total_recipients=1,
            sent_count=0,
            failed_count=1,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        _update_notification_status(db_session, notification.id)
        
        db_session.refresh(notification)
        assert notification.status == NotificationStatus.FAILED

    def test_update_status_partial(
        self, db_session, test_user
    ):
        """Status should be PARTIALLY_SENT when some fail."""
        notification = Notification(
            title="Test",
            message="Test",
            channels=["sms"],
            target_all=False,
            total_recipients=2,
            sent_count=1,
            failed_count=1,
            created_by_id=test_user.id,
        )
        db_session.add(notification)
        db_session.commit()
        
        _update_notification_status(db_session, notification.id)
        
        db_session.refresh(notification)
        assert notification.status == NotificationStatus.PARTIALLY_SENT
