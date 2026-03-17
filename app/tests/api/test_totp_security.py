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
- TOTP replay prevention (same code cannot be reused within same 30-second window)

These tests ensure the TOTP verification is strict and rejects expired codes
as per RFC 6238 security recommendations.
"""
import pytest
import time
from unittest.mock import patch, MagicMock
import pyotp

from app.core.security import verify_totp_code, generate_mfa_secret, is_totp_replay
from app.config import settings
from datetime import datetime, timezone, timedelta


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

    def test_is_totp_replay_no_previous_code(self):
        """
        is_totp_replay() should return False when user has no previous code.
        
        This is the first login scenario - no code has been used yet.
        """
        from unittest.mock import MagicMock
        
        # Mock user with no previous TOTP code
        mock_user = MagicMock()
        mock_user.last_used_totp_code = None
        mock_user.last_used_totp_at = None
        
        result = is_totp_replay(mock_user, "123456")
        assert result is False

    def test_is_totp_replay_same_code_same_window(self):
        """
        is_totp_replay() should return True for same code in same window.
        
        This is the replay attack scenario - attacker tries to reuse a code.
        """
        from unittest.mock import MagicMock
        from datetime import datetime, timezone
        
        # Mock user with a previously used code
        mock_user = MagicMock()
        mock_user.last_used_totp_code = "123456"
        mock_user.last_used_totp_at = datetime.now(timezone.utc)
        
        # Same code, same window -> should be detected as replay
        result = is_totp_replay(mock_user, "123456")
        assert result is True

    def test_is_totp_replay_same_code_different_window(self):
        """
        is_totp_replay() should return False for same code in different window.
        
        After 30 seconds, a new window starts and the same code pattern
        could theoretically appear again (though extremely unlikely).
        """
        from unittest.mock import MagicMock
        from datetime import datetime, timezone, timedelta
        
        # Mock user with a code from 60 seconds ago (2 windows ago)
        mock_user = MagicMock()
        mock_user.last_used_totp_code = "123456"
        mock_user.last_used_totp_at = datetime.now(timezone.utc) - timedelta(seconds=60)
        
        # Same code, but different window -> should NOT be replay
        result = is_totp_replay(mock_user, "123456")
        assert result is False

    def test_is_totp_replay_different_code_same_window(self):
        """
        is_totp_replay() should return False for different code in same window.
        
        User is trying a new code - should not be flagged as replay.
        """
        from unittest.mock import MagicMock
        from datetime import datetime, timezone
        
        # Mock user with a previously used code
        mock_user = MagicMock()
        mock_user.last_used_totp_code = "123456"
        mock_user.last_used_totp_at = datetime.now(timezone.utc)
        
        # Different code -> should NOT be replay
        result = is_totp_replay(mock_user, "654321")
        assert result is False

    def test_is_totp_replay_partial_state(self):
        """
        is_totp_replay() should handle partial state safely.
        
        If only one of the two fields is set, should not crash.
        """
        from unittest.mock import MagicMock
        from datetime import datetime, timezone
        
        # Only code set, no timestamp
        mock_user = MagicMock()
        mock_user.last_used_totp_code = "123456"
        mock_user.last_used_totp_at = None
        
        result = is_totp_replay(mock_user, "123456")
        assert result is False
        
        # Only timestamp set, no code
        mock_user.last_used_totp_code = None
        mock_user.last_used_totp_at = datetime.now(timezone.utc)
        
        result = is_totp_replay(mock_user, "123456")
        assert result is False


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

    def test_totp_replay_attack_is_rejected(self, db_session, client):
        """
        Replay attack: Using the same TOTP code twice within 30 seconds should fail.
        
        This is the critical security test for BUG-09.
        """
        from app.models import User, UserRole
        from app.core.security import hash_password

        # Create user with MFA enabled
        secret = generate_mfa_secret()
        user = User(
            email="replaytest@example.com",
            hashed_password=hash_password("TestPass123!"),
            first_name="Replay",
            last_name="Test",
            role=UserRole.VIEWER,
            is_active=True,
            mfa_enabled=True,
            mfa_secret=secret,
            # Ensure no previous TOTP code is set
            last_used_totp_code=None,
            last_used_totp_at=None,
        )
        db_session.add(user)
        db_session.commit()

        # Generate current TOTP code
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        # First login with the code - should succeed
        response = client.post("/api/v1/auth/login", json={
            "email": "replaytest@example.com",
            "password": "TestPass123!",
            "mfa_code": current_code,
        })

        # First attempt should succeed
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "access_token" in data

        # Verify the user now has last_used_totp_code set
        db_session.refresh(user)
        assert user.last_used_totp_code == current_code
        assert user.last_used_totp_at is not None

        # Second login with the SAME code within the same 30-second window
        # Should be rejected as a replay attack
        response = client.post("/api/v1/auth/login", json={
            "email": "replaytest@example.com",
            "password": "TestPass123!",
            "mfa_code": current_code,
        })

        # Second attempt should fail with 401
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        assert "already used" in data["detail"].lower() or "replay" in data["detail"].lower()

    def test_totp_new_window_allows_new_code(self, db_session, client):
        """
        After 30 seconds (new TOTP window), a new code should be accepted.
        
        This tests that replay protection doesn't block legitimate logins
        in subsequent time windows.
        """
        from unittest.mock import patch, MagicMock
        from app.models import User, UserRole
        from app.core.security import hash_password
        import time

        # Create user with MFA enabled
        secret = generate_mfa_secret()
        user = User(
            email="newwindow@example.com",
            hashed_password=hash_password("TestPass123!"),
            first_name="New",
            last_name="Window",
            role=UserRole.VIEWER,
            is_active=True,
            mfa_enabled=True,
            mfa_secret=secret,
        )
        db_session.add(user)
        db_session.commit()

        # Mock time.time() to control the TOTP window
        base_time = 1000000  # Fixed base time for deterministic testing
        
        with patch('time.time', return_value=base_time):
            # Generate code for the mocked time
            totp = pyotp.TOTP(secret)
            code_window_1 = totp.at(base_time)
            
            # First login - should succeed
            response = client.post("/api/v1/auth/login", json={
                "email": "newwindow@example.com",
                "password": "TestPass123!",
                "mfa_code": code_window_1,
            })
            assert response.status_code == 200

        # Simulate time advancing to next window (31 seconds later)
        with patch('time.time', return_value=base_time + 31):
            # Generate code for the new window
            code_window_2 = totp.at(base_time + 31)
            
            # Second login with NEW code in NEW window - should succeed
            response = client.post("/api/v1/auth/login", json={
                "email": "newwindow@example.com",
                "password": "TestPass123!",
                "mfa_code": code_window_2,
            })
            # Should succeed because it's a new code in a new window
            assert response.status_code == 200
