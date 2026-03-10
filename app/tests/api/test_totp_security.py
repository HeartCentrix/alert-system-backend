"""
Tests for TOTP Verification Security

Tests cover:
- Current-step TOTP code is accepted
- Previous-step/expired TOTP code is rejected
- Next-step TOTP code is rejected
- Malformed OTP is rejected
- Missing OTP is rejected
- Invalid stored secret fails safely
- Configurable valid_window behavior

These tests ensure the TOTP verification is strict and rejects expired codes
as per RFC 6238 security recommendations.
"""
import pytest
import time
from unittest.mock import patch, MagicMock
import pyotp

from app.core.security import verify_totp_code, generate_mfa_secret
from app.config import settings


class TestTOTPVerificationSecurity:
    """Test TOTP verification security properties."""

    def test_current_step_code_is_accepted(self):
        """Current valid TOTP code should be accepted."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Generate code for current time
        current_code = totp.now()
        
        # Should verify successfully
        assert verify_totp_code(secret, current_code) is True

    def test_expired_previous_step_code_is_rejected(self):
        """Expired code from previous time step should be rejected."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Get code for previous time step (30 seconds ago)
        previous_time = int(time.time()) - 30
        expired_code = totp.at(previous_time)
        
        # Should be rejected with default valid_window=0
        assert verify_totp_code(secret, expired_code) is False

    def test_next_step_code_is_rejected(self):
        """Code from next time step should be rejected."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Get code for next time step (30 seconds in future)
        next_time = int(time.time()) + 30
        future_code = totp.at(next_time)
        
        # Should be rejected with default valid_window=0
        assert verify_totp_code(secret, future_code) is False

    def test_malformed_otp_with_letters_is_rejected(self):
        """OTP containing letters should be rejected."""
        secret = generate_mfa_secret()
        
        # Should reject non-numeric codes
        assert verify_totp_code(secret, "ABC123") is False
        assert verify_totp_code(secret, "12345A") is False

    def test_malformed_otp_wrong_length_is_rejected(self):
        """OTP with wrong number of digits should be rejected."""
        secret = generate_mfa_secret()
        
        # Should reject codes that aren't exactly 6 digits
        assert verify_totp_code(secret, "12345") is False  # Too short
        assert verify_totp_code(secret, "1234567") is False  # Too long
        assert verify_totp_code(secret, "1234") is False  # Too short

    def test_empty_otp_is_rejected(self):
        """Empty or whitespace-only OTP should be rejected."""
        secret = generate_mfa_secret()
        
        assert verify_totp_code(secret, "") is False
        assert verify_totp_code(secret, "   ") is False
        assert verify_totp_code(secret, None) is False

    def test_invalid_secret_fails_safely(self):
        """Invalid or malformed secret should fail closed."""
        # Invalid base32 secret
        assert verify_totp_code("!!!INVALID!!!", "123456") is False
        assert verify_totp_code("", "123456") is False
        assert verify_totp_code(None, "123456") is False
        
        # Test with malformed secret that might cause exceptions
        # verify_totp_code should fail closed (return False) for any exception
        assert verify_totp_code("not-valid-base32!!!", "123456") is False
        assert verify_totp_code("12345!@#", "123456") is False

    def test_whitespace_in_code_is_stripped(self):
        """Leading/trailing whitespace in code should be stripped."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # Should accept code with whitespace
        assert verify_totp_code(secret, f" {current_code} ") is True
        assert verify_totp_code(secret, f"{current_code}   ") is True

    def test_secret_case_is_normalized(self):
        """Secret should be normalized to uppercase."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # Should work with lowercase secret
        lowercase_secret = secret.lower()
        assert verify_totp_code(lowercase_secret, current_code) is True
        
        # Should work with mixed case secret
        mixed_secret = secret.upper()
        assert verify_totp_code(mixed_secret, current_code) is True

    def test_secret_spaces_are_removed(self):
        """Spaces in secret should be removed during normalization."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # Should work with spaces in secret
        spaced_secret = secret.replace(secret[5:10], f" {secret[5:10]}")
        assert verify_totp_code(spaced_secret, current_code) is True


class TestTOTPValidWindowConfiguration:
    """Test configurable valid_window behavior."""

    def test_valid_window_zero_rejects_expired(self):
        """valid_window=0 should reject expired codes."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Get previous step code
        previous_time = int(time.time()) - 30
        expired_code = totp.at(previous_time)
        
        # Explicitly set valid_window=0
        assert verify_totp_code(secret, expired_code, valid_window=0) is False

    def test_valid_window_one_allows_previous_step(self):
        """valid_window=1 should allow one previous step."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Get previous step code
        previous_time = int(time.time()) - 30
        expired_code = totp.at(previous_time)
        
        # Explicitly set valid_window=1
        # This should accept the previous step
        assert verify_totp_code(secret, expired_code, valid_window=1) is True

    def test_valid_window_one_allows_next_step(self):
        """valid_window=1 should allow one future step."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Get next step code
        next_time = int(time.time()) + 30
        future_code = totp.at(next_time)
        
        # Explicitly set valid_window=1
        assert verify_totp_code(secret, future_code, valid_window=1) is True

    def test_valid_window_two_allows_wider_range(self):
        """valid_window=2 should allow two steps in either direction."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Get code from 2 steps ago (60 seconds)
        old_time = int(time.time()) - 60
        old_code = totp.at(old_time)
        
        # Should accept with valid_window=2
        assert verify_totp_code(secret, old_code, valid_window=2) is True

    def test_config_default_window_is_used_when_none(self):
        """When valid_window=None, config setting should be used."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Current code should always work regardless of window
        current_code = totp.now()
        assert verify_totp_code(secret, current_code, valid_window=None) is True
        
        # Previous code should follow config default
        previous_time = int(time.time()) - 30
        expired_code = totp.at(previous_time)
        
        # With default config (0), should reject
        result = verify_totp_code(secret, expired_code, valid_window=None)
        # This follows settings.MFA_TOTP_VALID_WINDOW which defaults to 0
        assert result is False


class TestTOTPReplayPrevention:
    """Test that TOTP codes cannot be replayed."""

    def test_same_code_cannot_be_reused_multiple_times(self, monkeypatch):
        """
        Same TOTP code should not be accepted multiple times.
        
        Note: This test documents the expected behavior, but actual
        replay prevention requires server-side code tracking which is
        not implemented in this basic TOTP verification.
        """
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # First verification should succeed
        assert verify_totp_code(secret, current_code) is True
        
        # Second verification with same code in same time step
        # will succeed with basic TOTP - this is a known limitation
        # Production systems should implement code replay detection
        assert verify_totp_code(secret, current_code) is True
        
        # This test documents that basic TOTP does not prevent replay
        # within the same time step - additional infrastructure needed

    def test_code_changes_every_time_step(self):
        """TOTP codes should change with each time step."""
        secret = generate_mfa_secret()
        totp = pyotp.TOTP(secret)
        
        # Get codes for consecutive time steps
        current_time = int(time.time())
        code_now = totp.at(current_time)
        code_next = totp.at(current_time + 30)
        code_prev = totp.at(current_time - 30)
        
        # All codes should be different
        assert code_now != code_next
        assert code_now != code_prev
        assert code_next != code_prev


class TestTOTPIntegrationWithLogin:
    """Integration tests for TOTP in login flow."""

    def test_login_with_current_totp_succeeds(self, db_session, client):
        """Login with current valid TOTP code should succeed."""
        from app.models import User, UserRole
        from app.core.security import hash_password
        
        # Create user with MFA enabled
        secret = generate_mfa_secret()
        user = User(
            email="totptest@example.com",
            hashed_password=hash_password("TestPass123!"),
            first_name="TOTP",
            last_name="Test",
            role=UserRole.VIEWER,
            is_active=True,
            mfa_enabled=True,
            mfa_secret=secret,
        )
        db_session.add(user)
        db_session.commit()
        
        # Generate current TOTP code
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        # Login with current code
        response = client.post("/api/v1/auth/login", json={
            "email": "totptest@example.com",
            "password": "TestPass123!",
            "mfa_code": current_code,
        })
        
        # Should succeed
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "access_token" in data

    def test_login_with_expired_totp_fails(self, db_session, client):
        """Login with expired TOTP code should fail."""
        from app.models import User, UserRole
        from app.core.security import hash_password
        
        # Create user with MFA enabled
        secret = generate_mfa_secret()
        user = User(
            email="expiredtotp@example.com",
            hashed_password=hash_password("TestPass123!"),
            first_name="Expired",
            last_name="TOTP",
            role=UserRole.VIEWER,
            is_active=True,
            mfa_enabled=True,
            mfa_secret=secret,
        )
        db_session.add(user)
        db_session.commit()
        
        # Generate expired TOTP code (from previous time step)
        totp = pyotp.TOTP(secret)
        previous_time = int(time.time()) - 30
        expired_code = totp.at(previous_time)
        
        # Login with expired code
        response = client.post("/api/v1/auth/login", json={
            "email": "expiredtotp@example.com",
            "password": "TestPass123!",
            "mfa_code": expired_code,
        })
        
        # Should fail with 401
        assert response.status_code == 401
        assert "Invalid credentials or MFA code" in response.json()["detail"]
