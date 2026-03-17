"""
Unit Tests for Messaging Service

Tests cover:
- Check-in link helpers
- Twilio SMS service
- Twilio voice calls
- Email service (SES)
- Error handling
- Mock mode behavior
"""
import pytest
from unittest.mock import MagicMock, patch

from app.services.messaging import (
    build_checkin_message,
    build_checkin_email_html,
    TwilioService,
    EmailService,
    _escape_xml,
)


# =============================================================================
# CHECK-IN LINK HELPER TESTS
# =============================================================================

class TestBuildCheckinMessage:
    """Test check-in message building."""

    def test_build_checkin_message_no_deadline(self):
        """Message without deadline should work."""
        result = build_checkin_message(
            notification_message="Are you okay?",
            checkin_url="https://example.com/checkin/abc123"
        )

        assert "Are you okay?" in result
        assert "SAFETY CHECK-IN REQUIRED" in result
        assert "https://example.com/checkin/abc123" in result
        assert "Click here to respond" in result

    def test_build_checkin_message_with_deadline(self):
        """Message with deadline should include time."""
        result = build_checkin_message(
            notification_message="Emergency alert",
            checkin_url="https://example.com/checkin/xyz",
            deadline_minutes=30
        )

        assert "Emergency alert" in result
        assert "within 30 minutes" in result
        assert "SAFETY CHECK-IN REQUIRED" in result

    def test_build_checkin_message_empty_message(self):
        """Empty message should still build check-in prompt."""
        result = build_checkin_message(
            notification_message="",
            checkin_url="https://example.com/checkin"
        )

        assert "SAFETY CHECK-IN REQUIRED" in result
        assert "Click here to respond" in result


class TestBuildCheckinEmailHtml:
    """Test HTML email building."""

    def test_build_checkin_email_html_basic(self):
        """Should add check-in button to HTML."""
        base_html = "<html><body><p>Test</p></body></html>"
        result = build_checkin_email_html(
            base_html=base_html,
            checkin_url="https://example.com/checkin"
        )

        assert "Safety Check-In Required" in result
        assert "https://example.com/checkin" in result
        assert "I'm Safe" in result
        assert "</body>" in result

    def test_build_checkin_email_html_with_deadline(self):
        """Should include deadline in HTML."""
        base_html = "<html><body><p>Test</p></body></html>"
        result = build_checkin_email_html(
            base_html=base_html,
            checkin_url="https://example.com/checkin",
            deadline_minutes=15
        )

        assert "within 15 minutes" in result

    def test_build_checkin_email_html_no_body_tag(self):
        """Should handle HTML without body tag."""
        base_html = "<div>No body tag</div>"
        result = build_checkin_email_html(
            base_html=base_html,
            checkin_url="https://example.com/checkin"
        )

        assert "Safety Check-In Required" in result
        assert "https://example.com/checkin" in result


# =============================================================================
# XML ESCAPE TESTS
# =============================================================================

class TestEscapeXml:
    """Test XML escaping for TwiML."""

    def test_escape_ampersand(self):
        """Should escape ampersands."""
        assert _escape_xml("A & B") == "A &amp; B"

    def test_escape_less_than(self):
        """Should escape less than."""
        assert _escape_xml("5 < 10") == "5 &lt; 10"

    def test_escape_greater_than(self):
        """Should escape greater than."""
        assert _escape_xml("10 > 5") == "10 &gt; 5"

    def test_escape_quotes(self):
        """Should escape quotes."""
        assert _escape_xml('Say "Hello"') == 'Say &quot;Hello&quot;'

    def test_escape_multiple(self):
        """Should escape multiple special chars."""
        result = _escape_xml("5 < 10 & 10 > 5")
        assert "&lt;" in result
        assert "&amp;" in result
        assert "&gt;" in result

    def test_escape_no_special_chars(self):
        """Should return unchanged if no special chars."""
        assert _escape_xml("Hello World") == "Hello World"

    def test_escape_none_input(self):
        """Should handle None input."""
        assert _escape_xml(None) == ""


# =============================================================================
# TWILIO SERVICE TESTS
# =============================================================================

class TestTwilioServiceInit:
    """Test Twilio service initialization."""

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.Client')
    def test_init_with_credentials(self, mock_client_class, mock_settings):
        """Should initialize with valid credentials."""
        mock_settings.TWILIO_ACCOUNT_SID = "AC123"
        mock_settings.TWILIO_AUTH_TOKEN = "token123"

        service = TwilioService()

        assert service.client is not None
        mock_client_class.assert_called_once()

    @patch('app.services.messaging.settings')
    def test_init_without_credentials(self, mock_settings):
        """Should handle missing credentials gracefully."""
        mock_settings.TWILIO_ACCOUNT_SID = None
        mock_settings.TWILIO_AUTH_TOKEN = None

        service = TwilioService()

        assert service.client is None


class TestTwilioSms:
    """Test Twilio SMS sending."""

    @patch('app.services.messaging.settings')
    def test_send_sms_mock_mode(self, mock_settings):
        """Should mock SMS when no credentials."""
        mock_settings.TWILIO_ACCOUNT_SID = None

        service = TwilioService()
        result = service.send_sms("+1234567890", "Test message")

        assert result["mock"] is True
        assert result["status"] == "sent"
        assert "MOCK" in result["sid"]

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.Client')
    def test_send_sms_real_mode(self, mock_client_class, mock_settings):
        """Should send real SMS with credentials."""
        mock_settings.TWILIO_ACCOUNT_SID = "AC123"
        mock_settings.TWILIO_AUTH_TOKEN = "token"
        mock_settings.TWILIO_FROM_NUMBER = "+1987654321"

        mock_client = MagicMock()
        mock_client.messages.create.return_value = MagicMock(
            sid="SM123",
            status="sent"
        )
        mock_client_class.return_value = mock_client

        service = TwilioService()
        result = service.send_sms("+1234567890", "Test message")

        assert result["sid"] == "SM123"
        assert result["status"] == "sent"
        mock_client.messages.create.assert_called_once()

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.Client')
    def test_send_sms_error_handling(self, mock_client_class, mock_settings):
        """Should handle SMS errors gracefully."""
        mock_settings.TWILIO_ACCOUNT_SID = "AC123"
        mock_settings.TWILIO_AUTH_TOKEN = "token"

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API Error")
        mock_client_class.return_value = mock_client

        service = TwilioService()
        result = service.send_sms("+1234567890", "Test")

        assert result["status"] == "failed"
        assert "error" in result


class TestTwilioVoice:
    """Test Twilio voice calls."""

    @patch('app.services.messaging.settings')
    def test_make_voice_call_mock_mode(self, mock_settings):
        """Should mock voice call when no credentials."""
        mock_settings.TWILIO_ACCOUNT_SID = None

        service = TwilioService()
        result = service.make_voice_call("+1234567890", "Emergency alert")

        assert result["mock"] is True
        assert result["status"] == "initiated"

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.Client')
    def test_make_voice_call_real_mode(self, mock_client_class, mock_settings):
        """Should make real voice call with credentials."""
        mock_settings.TWILIO_ACCOUNT_SID = "AC123"
        mock_settings.TWILIO_AUTH_TOKEN = "token"
        mock_settings.TWILIO_FROM_NUMBER = "+1987654321"
        mock_settings.BACKEND_URL = "https://api.example.com"

        mock_client = MagicMock()
        mock_client.calls.create.return_value = MagicMock(
            sid="CA123",
            status="in-progress"
        )
        mock_client_class.return_value = mock_client

        service = TwilioService()
        result = service.make_voice_call("+1234567890", "Press 1 if safe")

        assert result["sid"] == "CA123"
        assert result["status"] == "in-progress"
        mock_client.calls.create.assert_called_once()

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.Client')
    def test_make_voice_call_twiml_format(self, mock_client_class, mock_settings):
        """Should generate correct TwiML."""
        mock_settings.TWILIO_ACCOUNT_SID = "AC123"
        mock_settings.TWILIO_AUTH_TOKEN = "token"
        mock_settings.TWILIO_FROM_NUMBER = "+1987654321"
        mock_settings.BACKEND_URL = "https://api.example.com"

        mock_client = MagicMock()
        mock_client.calls.create.return_value = MagicMock(sid="CA123")
        mock_client_class.return_value = mock_client

        service = TwilioService()
        service.make_voice_call("+1234567890", "Test message")

        # Verify TwiML was passed
        call_args = mock_client.calls.create.call_args
        assert "twiml" in call_args.kwargs
        assert "<?xml" in call_args.kwargs["twiml"]
        assert "<Response>" in call_args.kwargs["twiml"]
        assert "<Say" in call_args.kwargs["twiml"]
        assert "<Gather" in call_args.kwargs["twiml"]

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.Client')
    def test_make_voice_call_error_handling(self, mock_client_class, mock_settings):
        """Should handle voice call errors gracefully."""
        mock_settings.TWILIO_ACCOUNT_SID = "AC123"
        mock_settings.TWILIO_AUTH_TOKEN = "token"

        mock_client = MagicMock()
        mock_client.calls.create.side_effect = Exception("Call failed")
        mock_client_class.return_value = mock_client

        service = TwilioService()
        result = service.make_voice_call("+1234567890", "Test")

        assert result["status"] == "failed"
        assert "error" in result


# =============================================================================
# EMAIL SERVICE TESTS
# =============================================================================

class TestEmailServiceInit:
    """Test Email service initialization."""

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.boto3')
    def test_init_with_credentials(self, mock_boto3, mock_settings):
        """Should initialize with valid AWS credentials."""
        mock_settings.AWS_ACCESS_KEY_ID = "AKIA123"
        mock_settings.AWS_SECRET_ACCESS_KEY = "secret"
        mock_settings.AWS_REGION = "us-east-1"

        service = EmailService()

        assert service.client is not None
        mock_boto3.client.assert_called_once()

    @patch('app.services.messaging.settings')
    def test_init_without_credentials(self, mock_settings):
        """Should handle missing credentials gracefully."""
        mock_settings.AWS_ACCESS_KEY_ID = None
        mock_settings.AWS_SECRET_ACCESS_KEY = None

        service = EmailService()

        assert service.client is None


class TestEmailServiceSend:
    """Test Email sending."""

    @patch('app.services.messaging.settings')
    def test_send_email_mock_mode(self, mock_settings):
        """Should mock email when no AWS credentials."""
        mock_settings.AWS_ACCESS_KEY_ID = None

        service = EmailService()
        result = service.send_email(
            to="test@example.com",
            subject="Test Subject",
            body_text="Test body"
        )

        assert result["mock"] is True
        assert result["status"] == "sent"
        assert "MOCK" in result["message_id"]

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.boto3')
    def test_send_email_real_mode(self, mock_boto3, mock_settings):
        """Should send real email with AWS credentials."""
        mock_settings.AWS_ACCESS_KEY_ID = "AKIA123"
        mock_settings.AWS_SECRET_ACCESS_KEY = "secret"
        mock_settings.AWS_REGION = "us-east-1"
        mock_settings.SES_FROM_NAME = "Test App"
        mock_settings.SES_FROM_EMAIL = "noreply@example.com"

        mock_client = MagicMock()
        mock_client.send_email.return_value = {"MessageId": "MSG123"}
        mock_boto3.client.return_value = mock_client

        service = EmailService()
        result = service.send_email(
            to="user@example.com",
            subject="Test",
            body_text="Hello"
        )

        assert result["message_id"] == "MSG123"
        assert result["status"] == "sent"
        mock_client.send_email.assert_called_once()

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.boto3')
    def test_send_email_with_html(self, mock_boto3, mock_settings):
        """Should send HTML email when provided."""
        mock_settings.AWS_ACCESS_KEY_ID = "AKIA123"
        mock_settings.AWS_SECRET_ACCESS_KEY = "secret"

        mock_client = MagicMock()
        mock_client.send_email.return_value = {"MessageId": "MSG123"}
        mock_boto3.client.return_value = mock_client

        service = EmailService()
        service.send_email(
            to="user@example.com",
            subject="Test",
            body_text="Plain text",
            body_html="<html><body>HTML</body></html>"
        )

        # Verify HTML was included
        call_args = mock_client.send_email.call_args
        message = call_args.kwargs["Message"]
        assert "Html" in message["Body"]

    @patch('app.services.messaging.settings')
    @patch('app.services.messaging.boto3')
    def test_send_email_error_handling(self, mock_boto3, mock_settings):
        """Should handle email errors gracefully."""
        mock_settings.AWS_ACCESS_KEY_ID = "AKIA123"
        mock_settings.AWS_SECRET_ACCESS_KEY = "secret"

        mock_client = MagicMock()
        mock_client.send_email.side_effect = Exception("SES Error")
        mock_boto3.client.return_value = mock_client

        service = EmailService()
        result = service.send_email(
            to="user@example.com",
            subject="Test",
            body_text="Hello"
        )

        assert result["status"] == "failed"
        assert "error" in result


class TestEmailServicePasswordReset:
    """Test password reset email."""

    @patch('app.services.messaging.settings')
    def test_send_password_reset_email_mock(self, mock_settings):
        """Should send password reset email."""
        mock_settings.AWS_ACCESS_KEY_ID = None
        mock_settings.FRONTEND_URL = "https://app.example.com"

        service = EmailService()
        result = service.send_password_reset_email(
            to="user@example.com",
            reset_token="token123",
            user_name="John Doe"
        )

        assert result["mock"] is True
        assert result["status"] == "sent"

    @patch('app.services.messaging.settings')
    def test_send_password_reset_email_contains_url(self, mock_settings):
        """Should include reset URL in email."""
        mock_settings.AWS_ACCESS_KEY_ID = None
        mock_settings.FRONTEND_URL = "https://app.example.com"

        service = EmailService()
        result = service.send_password_reset_email(
            to="user@example.com",
            reset_token="abc123",
            user_name="Jane"
        )

        # Reset URL should be in the email
        assert "https://app.example.com/reset-password" in str(result)
        assert "abc123" in str(result)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestMessagingIntegration:
    """Test messaging service integration."""

    @patch('app.services.messaging.settings')
    def test_all_services_mock_mode(self, mock_settings):
        """All services should work in mock mode."""
        mock_settings.TWILIO_ACCOUNT_SID = None
        mock_settings.AWS_ACCESS_KEY_ID = None

        twilio = TwilioService()
        email = EmailService()

        # SMS
        sms_result = twilio.send_sms("+1234567890", "Test")
        assert sms_result["mock"] is True

        # Voice
        voice_result = twilio.make_voice_call("+1234567890", "Test")
        assert voice_result["mock"] is True

        # Email
        email_result = email.send_email(
            to="test@example.com",
            subject="Test",
            body_text="Test"
        )
        assert email_result["mock"] is True
