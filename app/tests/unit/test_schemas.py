"""
Unit Tests for Pydantic Schemas

Tests cover:
- Input validation
- Field constraints
- Email validation
- Password requirements
- Role validation
- Edge cases
"""
import pytest
from pydantic import ValidationError, EmailError
from datetime import datetime, timezone

from app.schemas import (
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserUpdate,
    UserResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    ChangePasswordRequest,
    NotificationCreate,
    IncidentCreate,
)
from app.models import UserRole, AlertChannel, IncidentSeverity


# =============================================================================
# LOGIN REQUEST TESTS
# =============================================================================

class TestLoginRequest:
    """Test login request schema validation."""

    def test_login_request_valid(self):
        """Valid login request should pass."""
        request = LoginRequest(
            email="test@example.com",
            password="SecurePassword123!"
        )
        assert request.email == "test@example.com"
        assert request.password == "SecurePassword123!"

    def test_login_request_invalid_email(self):
        """Invalid email should fail validation."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                email="not-an-email",
                password="Password123!"
            )
        assert "email" in str(exc_info.value).lower()

    def test_login_request_empty_email(self):
        """Empty email should fail validation."""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="",
                password="Password123!"
            )

    def test_login_request_empty_password(self):
        """Empty password should be allowed (validated by auth logic)."""
        request = LoginRequest(
            email="test@example.com",
            password=""
        )
        assert request.password == ""

    def test_login_request_email_case(self):
        """Email should preserve case (validation is case-sensitive)."""
        request = LoginRequest(
            email="Test@Example.COM",
            password="Password123!"
        )
        assert request.email == "Test@Example.COM"

    def test_login_request_unicode_email(self):
        """Unicode in email should fail."""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="tëst@example.com",
                password="Password123!"
            )

    def test_login_request_long_password(self):
        """Very long password should be allowed."""
        long_password = "A" * 1000
        request = LoginRequest(
            email="test@example.com",
            password=long_password
        )
        assert request.password == long_password


# =============================================================================
# USER CREATE TESTS
# =============================================================================

class TestUserCreate:
    """Test user creation schema validation."""

    def test_user_create_minimal(self):
        """Minimal valid user creation."""
        user = UserCreate(
            email="test@example.com",
            password="SecurePassword123!",
            first_name="Test",
            last_name="User"
        )
        assert user.email == "test@example.com"
        assert user.role == UserRole.VIEWER  # Default role

    def test_user_create_full(self):
        """Full user creation with all fields."""
        user = UserCreate(
            email="test@example.com",
            password="SecurePassword123!",
            first_name="Test",
            last_name="User",
            phone="+1234567890",
            department="Engineering",
            title="Developer",
            employee_id="EMP001",
            role=UserRole.MANAGER,
            location_id=1,
            preferred_channels=["sms", "email"]
        )
        assert user.role == UserRole.MANAGER
        assert user.preferred_channels == ["sms", "email"]

    def test_user_create_invalid_email(self):
        """Invalid email should fail."""
        with pytest.raises(ValidationError):
            UserCreate(
                email="invalid-email",
                password="Password123!",
                first_name="Test",
                last_name="User"
            )

    def test_user_create_short_password(self):
        """Password shorter than 8 chars should fail."""
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(
                email="test@example.com",
                password="short",  # Less than 8 chars
                first_name="Test",
                last_name="User"
            )
        assert "length" in str(exc_info.value).lower() or "8" in str(exc_info.value)

    def test_user_create_valid_roles(self):
        """All valid roles should be accepted."""
        for role in UserRole:
            user = UserCreate(
                email="test@example.com",
                password="Password123!",
                first_name="Test",
                last_name="User",
                role=role
            )
            assert user.role == role

    def test_user_create_invalid_role(self):
        """Invalid role should fail."""
        with pytest.raises(ValidationError):
            UserCreate(
                email="test@example.com",
                password="Password123!",
                first_name="Test",
                last_name="User",
                role="invalid_role"
            )

    def test_user_create_empty_name(self):
        """Empty first/last name should be allowed (validated by business logic)."""
        user = UserCreate(
            email="test@example.com",
            password="Password123!",
            first_name="",
            last_name=""
        )
        assert user.first_name == ""
        assert user.last_name == ""

    def test_user_create_long_name(self):
        """Long names should be allowed (DB validates length)."""
        long_name = "A" * 200
        user = UserCreate(
            email="test@example.com",
            password="Password123!",
            first_name=long_name,
            last_name=long_name
        )
        assert user.first_name == long_name

    def test_user_create_invalid_preferred_channels(self):
        """Invalid channel values should fail."""
        with pytest.raises(ValidationError):
            UserCreate(
                email="test@example.com",
                password="Password123!",
                first_name="Test",
                last_name="User",
                preferred_channels=["invalid_channel"]
            )

    def test_user_create_phone_format(self):
        """Various phone formats should be allowed."""
        phone_formats = [
            "+1234567890",
            "1234567890",
            "+44 123 456 7890",
            "",
            None,
        ]
        for phone in phone_formats:
            user = UserCreate(
                email="test@example.com",
                password="Password123!",
                first_name="Test",
                last_name="User",
                phone=phone
            )
            assert user.phone == phone or phone is None


# =============================================================================
# PASSWORD RESET TESTS
# =============================================================================

class TestPasswordReset:
    """Test password reset schema validation."""

    def test_password_reset_request_valid(self):
        """Valid password reset request."""
        request = PasswordResetRequest(email="test@example.com")
        assert request.email == "test@example.com"

    def test_password_reset_request_invalid_email(self):
        """Invalid email should fail."""
        with pytest.raises(ValidationError):
            PasswordResetRequest(email="not-an-email")

    def test_password_reset_confirm_valid(self):
        """Valid password reset confirmation."""
        confirm = PasswordResetConfirm(
            token="reset_token_123",
            new_password="NewSecurePassword123!"
        )
        assert confirm.token == "reset_token_123"
        assert confirm.new_password == "NewSecurePassword123!"

    def test_password_reset_confirm_short_password(self):
        """Short new password should fail."""
        with pytest.raises(ValidationError):
            PasswordResetConfirm(
                token="reset_token_123",
                new_password="short"
            )

    def test_password_reset_confirm_empty_token(self):
        """Empty token should be allowed (validated by business logic)."""
        confirm = PasswordResetConfirm(
            token="",
            new_password="NewPassword123!"
        )
        assert confirm.token == ""


# =============================================================================
# CHANGE PASSWORD TESTS
# =============================================================================

class TestChangePassword:
    """Test change password schema validation."""

    def test_change_password_valid(self):
        """Valid change password request."""
        request = ChangePasswordRequest(
            current_password="OldPassword123!",
            new_password="NewPassword123!"
        )
        assert request.current_password == "OldPassword123!"
        assert request.new_password == "NewPassword123!"

    def test_change_password_short_new_password(self):
        """Short new password should fail."""
        with pytest.raises(ValidationError):
            ChangePasswordRequest(
                current_password="OldPassword123!",
                new_password="short"
            )

    def test_change_password_same_password(self):
        """Same current and new password should be allowed (validated by business logic)."""
        request = ChangePasswordRequest(
            current_password="SamePassword123!",
            new_password="SamePassword123!"
        )
        assert request.current_password == request.new_password


# =============================================================================
# NOTIFICATION CREATE TESTS
# =============================================================================

class TestNotificationCreate:
    """Test notification creation schema validation."""

    def test_notification_create_minimal(self):
        """Minimal valid notification."""
        notification = NotificationCreate(
            title="Test Alert",
            message="This is a test notification message",
            channels=[AlertChannel.SMS, AlertChannel.EMAIL],
            target_all=True
        )
        assert notification.title == "Test Alert"
        assert notification.target_all is True

    def test_notification_create_full(self):
        """Full notification with all fields."""
        from datetime import timedelta
        scheduled_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        notification = NotificationCreate(
            title="Test Alert",
            message="Test message",
            subject="Test Subject",
            channels=[AlertChannel.SMS, AlertChannel.EMAIL, AlertChannel.VOICE],
            target_all=False,
            target_group_ids=[1, 2, 3],
            target_user_ids=[4, 5, 6],
            incident_id=1,
            template_id=1,
            scheduled_at=scheduled_at,
            response_required=True,
            response_deadline_minutes=30,
            slack_webhook_url="https://hooks.slack.com/test",
            teams_webhook_url="https://webhook.test"
        )
        assert len(notification.channels) == 3
        assert notification.response_required is True

    def test_notification_create_empty_channels(self):
        """Empty channels should fail."""
        with pytest.raises(ValidationError):
            NotificationCreate(
                title="Test",
                message="Test",
                channels=[],
                target_all=True
            )

    def test_notification_create_invalid_channels(self):
        """Invalid channel values should fail."""
        with pytest.raises(ValidationError):
            NotificationCreate(
                title="Test",
                message="Test",
                channels=["invalid_channel"],
                target_all=True
            )

    def test_notification_create_no_recipients(self):
        """No recipient method should be allowed (validated by business logic)."""
        notification = NotificationCreate(
            title="Test",
            message="Test",
            channels=[AlertChannel.SMS],
            target_all=False
            # No groups or users specified
        )
        assert notification.target_all is False
        assert notification.target_group_ids is None

    def test_notification_create_long_message(self):
        """Very long message should be allowed."""
        long_message = "A" * 10000
        notification = NotificationCreate(
            title="Test",
            message=long_message,
            channels=[AlertChannel.SMS],
            target_all=True
        )
        assert notification.message == long_message


# =============================================================================
# INCIDENT CREATE TESTS
# =============================================================================

class TestIncidentCreate:
    """Test incident creation schema validation."""

    def test_incident_create_minimal(self):
        """Minimal valid incident."""
        incident = IncidentCreate(
            title="Test Incident"
        )
        assert incident.title == "Test Incident"
        assert incident.severity == IncidentSeverity.MEDIUM  # Default
        assert incident.status == IncidentStatus.ACTIVE  # Default

    def test_incident_create_full(self):
        """Full incident with all fields."""
        incident = IncidentCreate(
            title="Test Incident",
            type="weather",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.ACTIVE,
            description="This is a test incident description",
            location_id=1
        )
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.status == IncidentStatus.ACTIVE

    def test_incident_create_valid_severities(self):
        """All valid severities should be accepted."""
        for severity in IncidentSeverity:
            incident = IncidentCreate(
                title="Test",
                severity=severity
            )
            assert incident.severity == severity

    def test_incident_create_invalid_severity(self):
        """Invalid severity should fail."""
        with pytest.raises(ValidationError):
            IncidentCreate(
                title="Test",
                severity="invalid_severity"
            )

    def test_incident_create_valid_statuses(self):
        """All valid statuses should be accepted."""
        from app.models import IncidentStatus
        for status in IncidentStatus:
            incident = IncidentCreate(
                title="Test",
                status=status
            )
            assert incident.status == status


# =============================================================================
# EDGE CASES
# =============================================================================

class TestSchemaEdgeCases:
    """Test edge cases for all schemas."""

    def test_user_create_null_values(self):
        """None values should be handled correctly."""
        user = UserCreate(
            email="test@example.com",
            password="Password123!",
            first_name="Test",
            last_name="User",
            phone=None,
            department=None,
            title=None
        )
        assert user.phone is None
        assert user.department is None

    def test_notification_create_special_characters(self):
        """Special characters in title/message should be allowed."""
        notification = NotificationCreate(
            title="Test Alert! @#$%^&*()",
            message="Message with special chars: üñíçödé 🚨⚠️",
            channels=[AlertChannel.SMS],
            target_all=True
        )
        assert "🚨" in notification.message

    def test_user_create_whitespace_names(self):
        """Whitespace in names should be preserved."""
        user = UserCreate(
            email="test@example.com",
            password="Password123!",
            first_name="  Test  ",
            last_name="  User  "
        )
        assert user.first_name == "  Test  "
        assert user.last_name == "  User  "

    def test_all_schemas_extra_fields(self):
        """Extra fields should be ignored (pydantic behavior)."""
        # Pydantic v2 ignores extra fields by default
        data = {
            "email": "test@example.com",
            "password": "Password123!",
            "first_name": "Test",
            "last_name": "User",
            "extra_field": "should_be_ignored"
        }
        user = UserCreate(**data)
        assert user.email == "test@example.com"
        # extra_field should not exist on the model
