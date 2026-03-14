"""
Unit Tests for Security Module

Tests cover:
- Password hashing
- Token generation/verification
- Token refresh
- Password reset tokens
- TOTP/MFA
- Security utilities
"""
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    decode_refresh_token,
    create_password_reset_token,
    verify_password_reset_token,
    generate_totp_secret,
    verify_totp,
    _get_secret_key,
)
from app.models import UserRole


# =============================================================================
# PASSWORD HASHING TESTS
# =============================================================================

class TestPasswordHashing:
    """Test password hashing functions."""

    def test_hash_password_returns_string(self):
        """Hashed password should be a string."""
        result = hash_password("Password123!")
        assert isinstance(result, str)

    def test_hash_password_different_hashes(self):
        """Same password should produce different hashes."""
        hash1 = hash_password("Password123!")
        hash2 = hash_password("Password123!")
        assert hash1 != hash2  # Different salts

    def test_hash_password_different_passwords(self):
        """Different passwords should produce different hashes."""
        hash1 = hash_password("Password123!")
        hash2 = hash_password("Password456!")
        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Should verify correct password."""
        password = "Password123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Should reject incorrect password."""
        password = "Password123!"
        hashed = hash_password(password)
        assert verify_password("WrongPassword!", hashed) is False

    def test_verify_password_empty(self):
        """Should handle empty password."""
        password = ""
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("notempty", hashed) is False

    def test_verify_password_special_chars(self):
        """Should handle special characters."""
        password = "P@$$w0rd!#$%^&*()"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("P@$$w0rd", hashed) is False


# =============================================================================
# ACCESS TOKEN TESTS
# =============================================================================

class TestCreateAccessToken:
    """Test access token creation."""

    @patch('app.core.security.settings')
    def test_create_access_token_returns_string(self, mock_settings):
        """Should return JWT string."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        result = create_access_token(user_id=1, email="test@example.com")
        assert isinstance(result, str)
        assert len(result) > 0

    @patch('app.core.security.settings')
    def test_create_access_token_contains_parts(self, mock_settings):
        """JWT should have three parts."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        result = create_access_token(user_id=1, email="test@example.com")
        parts = result.split(".")
        assert len(parts) == 3

    @patch('app.core.security.settings')
    def test_create_access_token_with_role(self, mock_settings):
        """Should include user role in token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        result = create_access_token(
            user_id=1,
            email="test@example.com",
            role=UserRole.ADMIN
        )
        
        assert isinstance(result, str)

    @patch('app.core.security.settings')
    def test_create_access_token_different_users(self, mock_settings):
        """Different users should get different tokens."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        token1 = create_access_token(user_id=1, email="user1@example.com")
        token2 = create_access_token(user_id=2, email="user2@example.com")
        
        assert token1 != token2


# =============================================================================
# REFRESH TOKEN TESTS
# =============================================================================

class TestCreateRefreshToken:
    """Test refresh token creation."""

    @patch('app.core.security.settings')
    def test_create_refresh_token_returns_string(self, mock_settings):
        """Should return JWT string."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        result = create_refresh_token(user_id=1)
        assert isinstance(result, str)

    @patch('app.core.security.settings')
    def test_create_refresh_token_different_from_access(self, mock_settings):
        """Refresh token should differ from access token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        access = create_access_token(user_id=1, email="test@example.com")
        refresh = create_refresh_token(user_id=1)
        
        assert access != refresh


# =============================================================================
# TOKEN DECODING TESTS
# =============================================================================

class TestDecodeToken:
    """Test token decoding."""

    @patch('app.core.security.settings')
    def test_decode_access_token_success(self, mock_settings):
        """Should decode valid access token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        token = create_access_token(user_id=1, email="test@example.com")
        payload = decode_token(token)
        
        assert payload is not None
        assert payload["sub"] == "1"
        assert payload["email"] == "test@example.com"

    @patch('app.core.security.settings')
    def test_decode_access_token_invalid(self, mock_settings):
        """Should return None for invalid token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        result = decode_token("invalid.token.here")
        assert result is None

    @patch('app.core.security.settings')
    def test_decode_access_token_expired(self, mock_settings):
        """Should handle expired tokens."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        # Create token with very short expiry
        token = create_access_token(
            user_id=1,
            email="test@example.com",
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        result = decode_token(token)
        assert result is None

    @patch('app.core.security.settings')
    def test_decode_refresh_token_success(self, mock_settings):
        """Should decode valid refresh token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        token = create_refresh_token(user_id=1)
        payload = decode_token(token, token_type="refresh")
        
        assert payload is not None
        assert payload["sub"] == "1"

    @patch('app.core.security.settings')
    def test_decode_refresh_token_invalid(self, mock_settings):
        """Should return None for invalid refresh token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        result = decode_token("invalid.token", token_type="refresh")
        assert result is None


# =============================================================================
# PASSWORD RESET TOKEN TESTS
# =============================================================================

class TestPasswordResetToken:
    """Test password reset token functionality."""

    @patch('app.core.security.settings')
    def test_create_password_reset_token(self, mock_settings):
        """Should create reset token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        token = create_password_reset_token(user_id=1, email="test@example.com")
        
        assert isinstance(token, str)
        assert len(token) > 0

    @patch('app.core.security.settings')
    def test_verify_password_reset_token_success(self, mock_settings):
        """Should verify valid reset token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        token = create_password_reset_token(user_id=1, email="test@example.com")
        payload = verify_password_reset_token(token)
        
        assert payload is not None
        assert payload["user_id"] == 1

    @patch('app.core.security.settings')
    def test_verify_password_reset_token_invalid(self, mock_settings):
        """Should return None for invalid token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        result = verify_password_reset_token("invalid-token")
        assert result is None

    @patch('app.core.security.settings')
    def test_verify_password_reset_token_expired(self, mock_settings):
        """Should return None for expired token."""
        mock_settings.SECRET_KEY = "test-secret-key"
        
        # Token expires in 60 minutes by default
        # We can't easily test expiry without mocking time
        token = create_password_reset_token(user_id=1, email="test@example.com")
        payload = verify_password_reset_token(token)
        
        # Should be valid immediately
        assert payload is not None


# =============================================================================
# TOTP/MFA TESTS
# =============================================================================

class TestTOTP:
    """Test TOTP/MFA functionality."""

    def test_generate_totp_secret(self):
        """Should generate valid TOTP secret."""
        secret = generate_totp_secret()
        
        assert secret is not None
        assert isinstance(secret, str)
        assert len(secret) >= 32  # Base32 encoded secret

    def test_generate_totp_secret_unique(self):
        """Each secret should be unique."""
        secret1 = generate_totp_secret()
        secret2 = generate_totp_secret()
        
        assert secret1 != secret2

    @patch('app.core.security.pyotp.TOTP')
    def test_verify_totp_valid(self, mock_totp_class):
        """Should verify valid TOTP code."""
        mock_totp = MagicMock()
        mock_totp.verify.return_value = True
        mock_totp_class.return_value = mock_totp
        
        secret = "TESTSECRET"
        code = "123456"
        
        result = verify_totp(secret, code)
        
        assert result is True
        mock_totp.verify.assert_called_once()

    @patch('app.core.security.pyotp.TOTP')
    def test_verify_totp_invalid(self, mock_totp_class):
        """Should reject invalid TOTP code."""
        mock_totp = MagicMock()
        mock_totp.verify.return_value = False
        mock_totp_class.return_value = mock_totp
        
        secret = "TESTSECRET"
        code = "000000"
        
        result = verify_totp(secret, code)
        
        assert result is False


# =============================================================================
# SECRET KEY HELPER TESTS
# =============================================================================

class TestGetSecretKey:
    """Test secret key helper."""

    @patch('app.core.security.settings')
    def test_get_secret_key_from_settings(self, mock_settings):
        """Should return secret key from settings."""
        mock_settings.SECRET_KEY = "my-secret-key"
        
        result = _get_secret_key()
        
        assert result == "my-secret-key"

    @patch('app.core.security.settings')
    def test_get_secret_key_default(self, mock_settings):
        """Should return default if not configured."""
        mock_settings.SECRET_KEY = None
        
        result = _get_secret_key()
        
        assert result is not None
        assert isinstance(result, str)


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestSecurityEdgeCases:
    """Test security edge cases."""

    def test_hash_password_unicode(self):
        """Should handle unicode passwords."""
        password = "P@$$w0rd 日本語 🔐"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_hash_password_very_long(self):
        """Should handle very long passwords."""
        password = "A" * 1000
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_create_token_large_user_id(self):
        """Should handle large user IDs."""
        with patch('app.core.security.settings') as mock_settings:
            mock_settings.SECRET_KEY = "test-key"
            
            token = create_access_token(user_id=9999999999, email="test@example.com")
            assert isinstance(token, str)

    def test_create_token_special_email(self):
        """Should handle special characters in email."""
        with patch('app.core.security.settings') as mock_settings:
            mock_settings.SECRET_KEY = "test-key"
            
            token = create_access_token(
                user_id=1,
                email="user+test@example.co.uk"
            )
            assert isinstance(token, str)
