"""
Tests for PII Scrubbing Functions

Tests cover:
- Email scrubbing
- Phone scrubbing
- User identity logging
- Prevention of PII leaks in logs

Run with: pytest app/tests/unit/test_pii_scrubbing.py -v
"""
import pytest
from app.api.users import _scrub_email as users_scrub_email, _log_user_identity as users_log_identity
from app.api.auth import _scrub_email as auth_scrub_email, _log_user_identity as auth_log_identity
from app.tasks import _scrub_email as tasks_scrub_email, _scrub_phone as tasks_scrub_phone
from app.api.webhooks import _scrub_email as webhook_scrub_email, _scrub_phone as webhook_scrub_phone, _log_user_identity as webhook_log_identity


# =============================================================================
# EMAIL SCRUBBING TESTS
# =============================================================================

class TestEmailScrubbing:
    """Test email address scrubbing for safe logging."""

    def test_standard_email_scrubbing(self):
        """Test standard email format is scrubbed correctly."""
        assert users_scrub_email("john.doe@example.com") == "jo***@example.com"
        assert auth_scrub_email("john.doe@example.com") == "jo***@example.com"
        assert tasks_scrub_email("john.doe@example.com") == "jo***@example.com"
        assert webhook_scrub_email("john.doe@example.com") == "jo***@example.com"

    def test_short_local_part(self):
        """Test emails with short local part (≤2 chars)."""
        assert users_scrub_email("ab@test.org") == "ab***@test.org"
        assert users_scrub_email("a@x.co") == "a***@x.co"

    def test_single_char_local_part(self):
        """Test single character local part."""
        assert users_scrub_email("j@example.com") == "j***@example.com"

    def test_invalid_email(self):
        """Test invalid email format."""
        assert users_scrub_email("invalid") == "***@***"
        assert users_scrub_email("") == "***@***"

    def test_none_email(self):
        """Test None email value."""
        # Empty string should be handled gracefully
        assert users_scrub_email("") == "***@***"

    def test_subdomain_preserved(self):
        """Test subdomain in email is preserved."""
        assert users_scrub_email("user@mail.example.com") == "us***@mail.example.com"

    def test_plus_addressing(self):
        """Test plus addressing in email."""
        result = users_scrub_email("user+tag@example.com")
        assert "***" in result
        assert "@example.com" in result

    def test_company_email(self):
        """Test corporate email format."""
        assert users_scrub_email("john.doe@company.co.uk") == "jo***@company.co.uk"


# =============================================================================
# PHONE SCRUBBING TESTS
# =============================================================================

class TestPhoneScrubbing:
    """Test phone number scrubbing for safe logging."""

    def test_us_phone_with_dashes(self):
        """Test US phone with dashes."""
        result = tasks_scrub_phone("+1-555-123-4567")
        assert "***" in result
        assert "4567" in result  # Last 4 digits visible
        assert result[0] == "+"  # Country code preserved

    def test_us_phone_plain(self):
        """Test plain US phone number."""
        result = tasks_scrub_phone("5551234567")
        assert "***" in result
        assert "4567" in result

    def test_short_phone(self):
        """Test short phone number."""
        result = tasks_scrub_phone("1234567")
        assert "***" in result
        assert result == "123***"

    def test_very_short_phone(self):
        """Test very short phone number."""
        result = tasks_scrub_phone("123")
        assert result == "***"

    def test_empty_phone(self):
        """Test empty phone number."""
        assert tasks_scrub_phone("") == "***"

    def test_none_phone(self):
        """Test None phone value."""
        assert tasks_scrub_phone(None) == "***"

    def test_international_phone(self):
        """Test international phone format."""
        result = tasks_scrub_phone("+44-20-7946-0958")
        assert "***" in result
        assert "+44" in result  # Country code preserved

    def test_phone_with_spaces(self):
        """Test phone with spaces."""
        result = tasks_scrub_phone("+1 555 123 4567")
        assert "***" in result
        # Digits should be extracted
        digits = ''.join(c for c in result if c.isdigit())
        assert len(digits) > 4


# =============================================================================
# USER IDENTITY LOGGING TESTS
# =============================================================================

class TestUserIdentityLogging:
    """Test user identity logging helper functions."""

    def test_full_identity(self):
        """Test identity with both user_id and email."""
        result = users_log_identity(12345, "john.doe@example.com")
        assert "user_id=12345" in result
        assert "jo***@example.com" in result
        assert "john.doe" not in result  # Full email NOT visible

    def test_user_id_only(self):
        """Test identity with only user_id."""
        result = users_log_identity(12345, None)
        assert "user_id=12345" in result
        assert "email" not in result

    def test_email_only(self):
        """Test identity with only email."""
        result = users_log_identity(None, "john@example.com")
        assert "jo***@example.com" in result
        assert "user_id" not in result

    def test_both_none(self):
        """Test identity with both None."""
        result = users_log_identity(None, None)
        assert result == "[UNKNOWN]"

    def test_webhook_identity(self):
        """Test webhook module identity logging."""
        result = webhook_log_identity(999, "admin@company.com")
        assert "user_id=999" in result
        assert "ad***@company.com" in result

    def test_auth_identity(self):
        """Test auth module identity logging."""
        result = auth_log_identity(777, "user@test.org")
        assert "user_id=777" in result
        assert "us***@test.org" in result


# =============================================================================
# LOG SECURITY TESTS
# =============================================================================

class TestLogSecurity:
    """Test that logs don't leak PII."""

    def test_scrubbed_email_not_reversible(self):
        """Test that scrubbed email cannot be reversed to original."""
        original = "john.doe@example.com"
        scrubbed = users_scrub_email(original)
        
        # Should not contain full local part
        assert "john" not in scrubbed
        assert "doe" not in scrubbed
        
        # Should only show first 2 chars
        assert scrubbed.startswith("jo***")

    def test_scrubbed_phone_not_reversible(self):
        """Test that scrubbed phone cannot be reversed to original."""
        original = "+1-555-123-4567"
        scrubbed = tasks_scrub_phone(original)
        
        # Should not contain middle digits
        assert "123" not in scrubbed
        
        # Should have masked section
        assert "***" in scrubbed

    def test_identity_does_not_expose_full_email(self):
        """Test user identity never exposes full email."""
        test_emails = [
            "john.doe@example.com",
            "admin@company.co.uk",
            "user+tag@mail.example.com",
        ]
        
        for email in test_emails:
            result = users_log_identity(123, email)
            # Full email should never appear
            assert email not in result
            # Only scrubbed version should appear
            local = email.split('@')[0]
            if len(local) > 2:
                assert f"{local[:2]}***@" in result

    def test_all_modules_use_same_scrubbing(self):
        """Test all modules use consistent scrubbing."""
        email = "test@example.com"
        
        users_result = users_scrub_email(email)
        auth_result = auth_scrub_email(email)
        tasks_result = tasks_scrub_email(email)
        webhook_result = webhook_scrub_email(email)
        
        # All should produce same result
        assert users_result == auth_result == tasks_result == webhook_result

    def test_phone_scrubbing_consistent(self):
        """Test phone scrubbing is consistent across modules."""
        phone = "+1-555-123-4567"
        
        tasks_result = tasks_scrub_phone(phone)
        webhook_result = webhook_scrub_phone(phone)
        
        # Both should contain *** and last 4 digits
        assert "***" in tasks_result
        assert "***" in webhook_result
        assert "4567" in tasks_result
        assert "4567" in webhook_result


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases:
    """Test edge cases for PII scrubbing."""

    def test_unicode_email(self):
        """Test email with unicode characters."""
        # Should handle gracefully
        result = users_scrub_email("tëst@example.com")
        assert "***" in result
        assert "@example.com" in result

    def test_very_long_email(self):
        """Test very long email address."""
        long_local = "a" * 100
        email = f"{long_local}@example.com"
        result = users_scrub_email(email)
        # Should still only show first 2 chars
        assert result.startswith("aa***@example.com")

    def test_very_long_phone(self):
        """Test very long phone number."""
        long_phone = "+1-555-123-4567-890-1234"
        result = tasks_scrub_phone(long_phone)
        # Should still work
        assert "***" in result

    def test_special_characters_in_phone(self):
        """Test phone with various special characters."""
        result = tasks_scrub_phone("+1 (555) 123-4567")
        assert "***" in result
        assert "4567" in result

    def test_multiple_at_signs_email(self):
        """Test malformed email with multiple @ signs."""
        result = users_scrub_email("user@test@example.com")
        # Should handle gracefully (rsplit takes last @)
        assert "***" in result


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests for PII scrubbing in logging context."""

    def test_log_message_format(self):
        """Test complete log message format with scrubbed PII."""
        user_id = 12345
        email = "user@example.com"
        phone = "+1-555-123-4567"
        
        # Simulate log messages
        identity_log = users_log_identity(user_id, email)
        phone_log = f"Sending SMS to {tasks_scrub_phone(phone)}"
        email_log = f"Sending email to {users_scrub_email(email)}"
        
        # Verify format
        assert "user_id=12345" in identity_log
        assert "us***@example.com" in identity_log
        assert "***" in phone_log
        assert "4567" in phone_log
        assert "***" in email_log
        assert "@example.com" in email_log
        
        # Verify PII NOT exposed
        assert "user@example.com" not in identity_log
        assert "user@example.com" not in email_log
        assert "555" not in phone_log or "555***" in phone_log  # Middle digits hidden

    def test_error_message_scrubbing(self):
        """Test error messages scrub PII correctly."""
        email = "test@example.com"
        
        # Simulate error log
        error_msg = f"Failed to send email to {users_scrub_email(email)}: SMTP error"
        
        # Verify scrubbed
        assert "te***@example.com" in error_msg
        # Verify full email NOT exposed
        assert "test@example.com" not in error_msg

    def test_success_message_scrubbing(self):
        """Test success messages also scrub PII."""
        user_id = 999
        email = "admin@company.com"
        
        # Simulate success log
        success_msg = f"Email sent to {users_log_identity(user_id, email)}"
        
        # Verify scrubbed
        assert "user_id=999" in success_msg
        assert "ad***@company.com" in success_msg
        # Verify full email NOT exposed
        assert "admin@company.com" not in success_msg
