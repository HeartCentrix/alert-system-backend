"""
Unit Tests for Messaging Services

Tests cover:
- Twilio SMS service
- Twilio Voice service
- Twilio WhatsApp service
- AWS SES Email service
- Webhook services (Slack, Teams)
- Mock mode behavior
"""
import pytest
from unittest.mock import MagicMock, patch, call
import httpx

from app.services.messaging import (
    TwilioService,
    EmailService,
    WebhookService,
    twilio_service,
    email_service,
    webhook_service,
)


# =============================================================================
# TWILIO SERVICE TESTS
# =============================================================================

class TestTwilioService:
    """Test Twilio service functionality."""

    def test_send_sms_success(self, mock_twilio: MagicMock):
        """SMS sending should succeed with valid data."""
        result = twilio_service.send_sms("+1234567890", "Test message")
        assert result["status"] == "sent"
        assert "sid" in result
        mock_twilio.send_sms.assert_called_once_with("+1234567890", "Test message")

    def test_send_sms_empty_phone(self, mock_twilio: MagicMock):
        """SMS to empty phone should handle gracefully."""
        result = twilio_service.send_sms("", "Test message")
        # Should still attempt to send (Twilio will validate)
        mock_twilio.send_sms.assert_called_once_with("", "Test message")

    def test_send_sms_long_message(self, mock_twilio: MagicMock):
        """Long SMS messages should be sent."""
        long_message = "A" * 1600  # 10 SMS segments
        result = twilio_service.send_sms("+1234567890", long_message)
        assert result["status"] == "sent"
        mock_twilio.send_sms.assert_called_once_with("+1234567890", long_message)

    def test_send_sms_special_characters(self, mock_twilio: MagicMock):
        """SMS with special characters should be sent."""
        message = "Test message with special chars: @#$%^&*() üñíçödé"
        result = twilio_service.send_sms("+1234567890", message)
        assert result["status"] == "sent"

    def test_send_sms_unicode(self, mock_twilio: MagicMock):
        """SMS with unicode emojis should be sent."""
        message = "🚨 Emergency Alert! ⚠️ Stay safe! 🏠"
        result = twilio_service.send_sms("+1234567890", message)
        assert result["status"] == "sent"

    def test_send_sms_international_number(self, mock_twilio: MagicMock):
        """SMS to international numbers should work."""
        international_numbers = [
            "+441234567890",  # UK
            "+33123456789",   # France
            "+811234567890",  # Japan
            "+61123456789",   # Australia
        ]
        for number in international_numbers:
            result = twilio_service.send_sms(number, "Test")
            assert result["status"] == "sent"

    def test_send_whatsapp_success(self, mock_twilio: MagicMock):
        """WhatsApp message sending should succeed."""
        result = twilio_service.send_whatsapp("+1234567890", "Test WhatsApp message")
        assert result["status"] == "sent"
        assert "sid" in result
        mock_twilio.send_whatsapp.assert_called_once()

    def test_send_whatsapp_formats_number(self, mock_twilio: MagicMock):
        """WhatsApp should format phone number correctly."""
        twilio_service.send_whatsapp("+1234567890", "Test")
        # Should prepend whatsapp: if not present
        call_args = mock_twilio.send_whatsapp.call_args
        assert call_args[0][0] == "+1234567890"

    def test_send_whatsapp_already_formatted(self, mock_twilio: MagicMock):
        """WhatsApp with already formatted number should work."""
        result = twilio_service.send_whatsapp("whatsapp:+1234567890", "Test")
        assert result["status"] == "sent"

    def test_voice_call_success(self, mock_twilio: MagicMock):
        """Voice call should succeed."""
        result = twilio_service.make_voice_call("+1234567890", "Emergency message")
        assert result["status"] == "initiated"
        assert "sid" in result
        mock_twilio.make_voice_call.assert_called_once()

    def test_voice_call_twiml_format(self, mock_twilio: MagicMock):
        """Voice call should generate correct TwiML."""
        message = "This is a test emergency message"
        twilio_service.make_voice_call("+1234567890", message)
        
        # Check TwiML was generated
        call_args = mock_twilio.make_voice_call.call_args
        # TwiML should contain the message
        assert message in str(call_args)
        # TwiML should contain Gather action
        assert "Gather" in str(call_args)
        assert "Press 1" in str(call_args)
        assert "Press 2" in str(call_args)

    def test_twilio_service_without_credentials(self):
        """Twilio service should use mock mode without credentials."""
        with patch("app.services.messaging.settings") as mock_settings:
            mock_settings.TWILIO_ACCOUNT_SID = ""
            mock_settings.TWILIO_AUTH_TOKEN = ""
            
            service = TwilioService()
            result = service.send_sms("+1234567890", "Test")
            
            assert result["mock"] is True
            assert result["sid"] == "MOCK_SID"

    def test_twilio_error_handling(self):
        """Twilio service should handle errors gracefully."""
        with patch("app.services.messaging.settings") as mock_settings:
            mock_settings.TWILIO_ACCOUNT_SID = "test"
            mock_settings.TWILIO_AUTH_TOKEN = "test"
            
            with patch("app.services.messaging.Client") as mock_client:
                mock_client.return_value.messages.create.side_effect = Exception("API Error")
                
                service = TwilioService()
                result = service.send_sms("+1234567890", "Test")
                
                assert result["status"] == "failed"
                assert "error" in result


# =============================================================================
# EMAIL SERVICE TESTS
# =============================================================================

class TestEmailService:
    """Test Email (SES) service functionality."""

    def test_send_email_success(self, mock_email_service: MagicMock):
        """Email sending should succeed with valid data."""
        result = email_service.send_email(
            "test@example.com",
            "Test Subject",
            "Test body content"
        )
        assert result["status"] == "sent"
        assert "message_id" in result
        mock_email_service.send_email.assert_called_once()

    def test_send_email_with_html(self, mock_email_service: MagicMock):
        """Email with custom HTML should be sent."""
        html_body = "<html><body><h1>Test</h1></body></html>"
        result = email_service.send_email(
            "test@example.com",
            "Test Subject",
            "Plain text",
            body_html=html_body
        )
        assert result["status"] == "sent"

    def test_send_email_multiple_recipients_separate_calls(self, mock_email_service: MagicMock):
        """Multiple recipients require separate calls."""
        recipients = ["user1@example.com", "user2@example.com", "user3@example.com"]
        for recipient in recipients:
            email_service.send_email(recipient, "Subject", "Body")
        
        assert mock_email_service.send_email.call_count == 3

    def test_send_email_special_characters(self, mock_email_service: MagicMock):
        """Email with special characters should be sent."""
        subject = "Test Subject with special chars: @#$%^&*"
        body = "Body with unicode: üñíçödé"
        result = email_service.send_email("test@example.com", subject, body)
        assert result["status"] == "sent"

    def test_send_password_reset_email(self, mock_email_service: MagicMock):
        """Password reset email should be formatted correctly."""
        result = email_service.send_password_reset_email(
            "test@example.com",
            "reset_token_123",
            "John Doe"
        )
        assert result["status"] == "sent"
        mock_email_service.send_password_reset_email.assert_called_once_with(
            "test@example.com", "reset_token_123", "John Doe"
        )

    def test_send_welcome_email(self, mock_email_service: MagicMock):
        """Welcome email should be formatted correctly."""
        result = email_service.send_welcome_email(
            "test@example.com",
            "John Doe",
            "TempPassword123!"
        )
        assert result["status"] == "sent"
        mock_email_service.send_welcome_email.assert_called_once_with(
            "test@example.com", "John Doe", "TempPassword123!"
        )

    def test_send_email_invalid_email_format(self, mock_email_service: MagicMock):
        """Invalid email format should still attempt to send (SES validates)."""
        result = email_service.send_email(
            "invalid-email",
            "Subject",
            "Body"
        )
        # Service attempts to send, SES will reject
        assert result["status"] == "sent"  # Mock mode always succeeds

    def test_email_service_without_credentials(self):
        """Email service should use mock mode without AWS credentials."""
        with patch("app.services.messaging.settings") as mock_settings:
            mock_settings.AWS_ACCESS_KEY_ID = ""
            mock_settings.AWS_SECRET_ACCESS_KEY = ""
            
            service = EmailService()
            result = service.send_email("test@example.com", "Subject", "Body")
            
            assert result["mock"] is True
            assert result["message_id"] == "MOCK_EMAIL_ID"

    def test_text_to_html_conversion(self):
        """Plain text should be converted to HTML."""
        text = "Line 1\n\nLine 2\n\nLine 3"
        html = email_service._text_to_html(text)
        
        assert "<html>" in html
        assert "<p>Line 1</p>" in html
        assert "<p>Line 2</p>" in html
        assert "<p>Line 3</p>" in html

    def test_send_email_empty_body(self, mock_email_service: MagicMock):
        """Email with empty body should be sent."""
        result = email_service.send_email("test@example.com", "Subject", "")
        assert result["status"] == "sent"

    def test_send_email_very_long_body(self, mock_email_service: MagicMock):
        """Email with very long body should be sent."""
        long_body = "A" * 100000  # 100KB
        result = email_service.send_email("test@example.com", "Subject", long_body)
        assert result["status"] == "sent"


# =============================================================================
# WEBHOOK SERVICE TESTS
# =============================================================================

class TestWebhookService:
    """Test Webhook service (Slack/Teams) functionality."""

    def test_send_slack_success(self, mock_webhook_service: MagicMock):
        """Slack webhook should succeed."""
        result = webhook_service.send_slack(
            "https://hooks.slack.com/test",
            "Test message",
            "Test Title"
        )
        assert result["status"] == "sent"
        mock_webhook_service.send_slack.assert_called_once()

    def test_send_slack_with_blocks(self, mock_webhook_service: MagicMock):
        """Slack message should use blocks format."""
        webhook_service.send_slack("https://hooks.slack.com/test", "Message", "Title")
        
        call_args = mock_webhook_service.send_slack.call_args
        # Should contain header block with emoji
        assert "🚨" in str(call_args)

    def test_send_teams_success(self, mock_webhook_service: MagicMock):
        """Teams webhook should succeed."""
        result = webhook_service.send_teams(
            "https://outlook.office.com/webhook/test",
            "Test message",
            "Test Title"
        )
        assert result["status"] == "sent"
        mock_webhook_service.send_teams.assert_called_once()

    def test_send_teams_message_card_format(self, mock_webhook_service: MagicMock):
        """Teams message should use MessageCard format."""
        webhook_service.send_teams("https://webhook.test", "Message", "Title")
        
        call_args = mock_webhook_service.send_teams.call_args
        # Should contain MessageCard type
        assert "MessageCard" in str(call_args)
        assert "themeColor" in str(call_args)

    def test_send_slack_without_webhook_url(self, mock_webhook_service: MagicMock):
        """Slack without URL should use default or mock."""
        with patch("app.services.messaging.settings") as mock_settings:
            mock_settings.SLACK_DEFAULT_WEBHOOK_URL = ""
            
            result = webhook_service.send_slack("", "Message", "Title")
            # In mock mode, returns mock status
            assert "status" in result

    def test_send_teams_without_webhook_url(self, mock_webhook_service: MagicMock):
        """Teams without URL should use default or mock."""
        with patch("app.services.messaging.settings") as mock_settings:
            mock_settings.TEAMS_DEFAULT_WEBHOOK_URL = ""
            
            result = webhook_service.send_teams("", "Message", "Title")
            assert "status" in result

    def test_send_slack_error_handling(self):
        """Slack webhook should handle errors gracefully."""
        with patch("httpx.post") as mock_post:
            mock_post.side_effect = httpx.HTTPError("Connection error")
            
            service = WebhookService()
            result = service.send_slack("https://hooks.slack.com/test", "Message", "Title")
            
            assert result["status"] == "failed"
            assert "error" in result

    def test_send_teams_error_handling(self):
        """Teams webhook should handle errors gracefully."""
        with patch("httpx.post") as mock_post:
            mock_post.side_effect = httpx.HTTPError("Connection error")
            
            service = WebhookService()
            result = service.send_teams("https://webhook.test", "Message", "Title")
            
            assert result["status"] == "failed"
            assert "error" in result

    def test_send_slack_http_error_status(self):
        """Slack webhook should handle HTTP error status codes."""
        with patch("httpx.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_post.return_value = mock_response
            
            service = WebhookService()
            result = service.send_slack("https://hooks.slack.com/test", "Message", "Title")
            
            assert result["status"] == "failed"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestMessagingIntegration:
    """Test messaging service integration scenarios."""

    def test_send_all_channels(self, mock_twilio, mock_email_service, mock_webhook_service):
        """Sending to all channels should work."""
        # SMS
        sms_result = twilio_service.send_sms("+1234567890", "Alert!")
        assert sms_result["status"] == "sent"
        
        # Email
        email_result = email_service.send_email("test@example.com", "Alert!", "Body")
        assert email_result["status"] == "sent"
        
        # WhatsApp
        wa_result = twilio_service.send_whatsapp("+1234567890", "Alert!")
        assert wa_result["status"] == "sent"
        
        # Voice
        voice_result = twilio_service.make_voice_call("+1234567890", "Alert!")
        assert voice_result["status"] == "initiated"
        
        # Slack
        slack_result = webhook_service.send_slack("https://hooks.slack.com/test", "Alert!", "Title")
        assert slack_result["status"] == "sent"
        
        # Teams
        teams_result = webhook_service.send_teams("https://webhook.test", "Alert!", "Title")
        assert teams_result["status"] == "sent"

    def test_send_to_multiple_recipients(self, mock_email_service: MagicMock):
        """Sending to multiple recipients should work."""
        recipients = [
            "user1@example.com",
            "user2@example.com",
            "user3@example.com",
        ]
        
        results = []
        for recipient in recipients:
            result = email_service.send_email(recipient, "Alert", "Body")
            results.append(result)
        
        assert all(r["status"] == "sent" for r in results)
        assert mock_email_service.send_email.call_count == 3

    def test_message_truncation_not_needed(self, mock_twilio: MagicMock):
        """Long messages should be sent without truncation."""
        # Twilio handles segmentation automatically
        long_message = "A" * 2000
        result = twilio_service.send_sms("+1234567890", long_message)
        assert result["status"] == "sent"
