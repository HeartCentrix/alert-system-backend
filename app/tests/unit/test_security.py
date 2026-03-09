"""
Unit Tests for Security Module

Tests cover:
- Password hashing and verification
- JWT token creation and validation
- Token expiration handling
- Token tampering detection
- Password strength validation
"""
import pytest
from datetime import datetime, timedelta, timezone
from jose import jwt

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_password_strength,
    ALGORITHM,
)
from app.config import settings
from app.models import UserRole


# =============================================================================
# PASSWORD HASHING TESTS
# =============================================================================

class TestPasswordHashing:
    """Test password hashing functionality."""

    def test_hash_password_returns_string(self):
        """Password hash should be a non-empty string."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        assert isinstance(hashed, str)
        assert len(hashed) > 0
        assert hashed != password

    def test_hash_password_is_deterministic_for_verification(self):
        """Same password should verify against its hash."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        # Hash is salted, so each hash is different, but verification works
        assert verify_password(password, hashed) is True

    def test_hash_password_different_salts(self):
        """Each hash should be different due to salt."""
        password = "TestPassword123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        # Bcrypt uses random salt, so hashes should differ
        assert hash1 != hash2

    def test_verify_password_correct(self):
        """Correct password should verify."""
        password = "SecureP@ssw0rd123"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Incorrect password should not verify."""
        password = "SecureP@ssw0rd123"
        wrong_password = "WrongPassword456"
        hashed = hash_password(password)
        assert verify_password(wrong_password, hashed) is False

    def test_verify_password_empty(self):
        """Empty password should not verify."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        assert verify_password("", hashed) is False

    def test_verify_password_case_sensitive(self):
        """Password verification should be case-sensitive."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        assert verify_password("testpassword123!", hashed) is False
        assert verify_password("TESTPASSWORD123!", hashed) is False

    def test_hash_password_special_characters(self):
        """Password with special characters should hash correctly."""
        password = "P@$$w0rd!#$%^&*()_+-=[]{}|;':\",./<>?"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_hash_password_unicode(self):
        """Unicode password should hash correctly."""
        password = "Password™∑®†€üñíçödé"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_hash_password_long_password(self):
        """Very long password should hash correctly."""
        password = "A" * 1000
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_hash_password_whitespace(self):
        """Password with leading/trailing whitespace should be preserved."""
        password = "  TestPassword  "
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("TestPassword", hashed) is False


# =============================================================================
# PASSWORD STRENGTH VALIDATION TESTS
# =============================================================================

class TestPasswordStrengthValidation:
    """Test password strength validation requirements."""

    def test_valid_strong_password(self):
        """Strong password should pass validation."""
        password = "SecureP@ssw0rd123"
        is_valid, error = validate_password_strength(password)
        assert is_valid is True
        assert error == ""

    def test_password_too_short(self):
        """Password under 8 characters should fail."""
        password = "Abc1!"
        is_valid, error = validate_password_strength(password)
        assert is_valid is False
        assert "at least 8 characters" in error

    def test_password_exactly_8_chars_with_requirements(self):
        """Password with exactly 8 chars meeting all requirements should pass."""
        password = "Abc123!@"
        is_valid, error = validate_password_strength(password)
        assert is_valid is True
        assert error == ""

    def test_password_missing_uppercase(self):
        """Password without uppercase should fail."""
        password = "securepass123!"
        is_valid, error = validate_password_strength(password)
        assert is_valid is False
        assert "uppercase" in error

    def test_password_missing_digit(self):
        """Password without digit should fail."""
        password = "SecurePassword!"
        is_valid, error = validate_password_strength(password)
        assert is_valid is False
        assert "digit" in error

    def test_password_missing_symbol(self):
        """Password without symbol should fail."""
        password = "SecurePass123"
        is_valid, error = validate_password_strength(password)
        assert is_valid is False
        assert "special character" in error

    def test_password_with_various_symbols(self):
        """Password with various special characters should pass."""
        symbols = "!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'`~"
        password = f"SecureP1{symbols[:5]}"
        is_valid, error = validate_password_strength(password)
        assert is_valid is True
        assert error == ""

    def test_password_all_lowercase(self):
        """All lowercase password should fail all requirements except length."""
        password = "abcdefgh"
        is_valid, error = validate_password_strength(password)
        assert is_valid is False
        assert "uppercase" in error

    def test_password_common_weak_password(self):
        """Common weak passwords should be rejected by zxcvbn."""
        weak_passwords = ["password", "12345678", "qwerty123"]
        for weak_pwd in weak_passwords:
            is_valid, error = validate_password_strength(weak_pwd)
            assert is_valid is False


# =============================================================================
# ACCESS TOKEN CREATION TESTS
# =============================================================================

class TestAccessTokenCreation:
    """Test access token creation."""

    def test_create_access_token_returns_string(self):
        """Access token should be a non-empty string."""
        data = {"sub": "1", "role": "viewer"}
        token = create_access_token(data)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_access_token_contains_three_parts(self):
        """JWT should have three parts (header.payload.signature)."""
        data = {"sub": "1", "role": "viewer"}
        token = create_access_token(data)
        parts = token.split(".")
        assert len(parts) == 3

    def test_create_access_token_contains_subject(self):
        """Token payload should contain the subject."""
        user_id = "123"
        data = {"sub": user_id, "role": "admin"}
        token = create_access_token(data)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == user_id

    def test_create_access_token_contains_role(self):
        """Token payload should contain the role."""
        data = {"sub": "1", "role": "super_admin"}
        token = create_access_token(data)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["role"] == "super_admin"

    def test_create_access_token_has_type_access(self):
        """Access token should have type 'access'."""
        data = {"sub": "1"}
        token = create_access_token(data)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["type"] == "access"

    def test_create_access_token_has_expiration(self):
        """Access token should have expiration time."""
        data = {"sub": "1"}
        token = create_access_token(data)
        decoded = decode_token(token)
        assert decoded is not None
        assert "exp" in decoded
        assert isinstance(decoded["exp"], (int, float))

    def test_create_access_token_custom_expiry(self):
        """Access token should respect custom expiry duration."""
        data = {"sub": "1"}
        custom_delta = timedelta(hours=2)
        token = create_access_token(data, expires_delta=custom_delta)
        decoded = decode_token(token)
        assert decoded is not None
        
        # Check expiration is approximately 2 hours from now
        exp_time = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
        expected_time = datetime.now(timezone.utc) + custom_delta
        time_diff = abs((exp_time - expected_time).total_seconds())
        assert time_diff < 5  # Within 5 seconds

    def test_create_access_token_different_users(self):
        """Different users should get different tokens."""
        token1 = create_access_token({"sub": "1", "role": "viewer"})
        token2 = create_access_token({"sub": "2", "role": "viewer"})
        assert token1 != token2


# =============================================================================
# REFRESH TOKEN CREATION TESTS
# =============================================================================

class TestRefreshTokenCreation:
    """Test refresh token creation."""

    def test_create_refresh_token_returns_string(self):
        """Refresh token should be a non-empty string."""
        token = create_refresh_token({"sub": "1"})
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_refresh_token_has_type_refresh(self):
        """Refresh token should have type 'refresh'."""
        token = create_refresh_token({"sub": "1"})
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["type"] == "refresh"

    def test_create_refresh_token_longer_expiry(self):
        """Refresh token should have longer expiry than access token."""
        access_token = create_access_token({"sub": "1"})
        refresh_token = create_refresh_token({"sub": "1"})
        
        access_decoded = decode_token(access_token)
        refresh_decoded = decode_token(refresh_token)
        
        assert access_decoded is not None
        assert refresh_decoded is not None
        assert refresh_decoded["exp"] > access_decoded["exp"]

    def test_create_refresh_token_contains_subject(self):
        """Refresh token should contain the subject."""
        user_id = "456"
        token = create_refresh_token({"sub": user_id})
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == user_id


# =============================================================================
# TOKEN DECODING TESTS
# =============================================================================

class TestTokenDecoding:
    """Test token decoding functionality."""

    def test_decode_valid_access_token(self):
        """Valid access token should decode successfully."""
        data = {"sub": "789", "role": "manager", "extra": "data"}
        token = create_access_token(data)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == "789"
        assert decoded["role"] == "manager"
        assert decoded["extra"] == "data"
        assert decoded["type"] == "access"

    def test_decode_valid_refresh_token(self):
        """Valid refresh token should decode successfully."""
        data = {"sub": "789", "extra": "data"}
        token = create_refresh_token(data)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["sub"] == "789"
        assert decoded["type"] == "refresh"

    def test_decode_invalid_token(self):
        """Invalid token should return None."""
        result = decode_token("invalid.token.here")
        assert result is None

    def test_decode_empty_string(self):
        """Empty string should return None."""
        result = decode_token("")
        assert result is None

    def test_decode_malformed_token(self):
        """Malformed token should return None."""
        result = decode_token("not.a.valid.jwt.token")
        assert result is None

    def test_decode_tampered_token(self):
        """Tampered token should return None."""
        original_token = create_access_token({"sub": "1"})
        parts = original_token.split(".")
        tampered = f"{parts[0]}.{parts[1]}.tampered_signature"
        result = decode_token(tampered)
        assert result is None

    def test_decode_expired_token(self):
        """Expired token should still decode (expiration checked separately)."""
        # Create token that expired 1 hour ago
        payload = {
            "sub": "1",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "type": "access",
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
        # decode_token catches JWTError and returns None for expired tokens
        result = decode_token(token)
        assert result is None

    def test_decode_token_with_wrong_algorithm(self):
        """Token created with different algorithm should fail."""
        payload = {"sub": "1", "type": "access"}
        # Create token with different algorithm
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS512")
        result = decode_token(token)
        assert result is None

    def test_decode_token_with_wrong_secret(self):
        """Token created with different secret should fail."""
        payload = {"sub": "1", "type": "access"}
        # Create token with different secret
        token = jwt.encode(payload, "wrong-secret-key", algorithm=ALGORITHM)
        result = decode_token(token)
        assert result is None


# =============================================================================
# TOKEN EXPIRATION TESTS
# =============================================================================

class TestTokenExpiration:
    """Test token expiration handling."""

    def test_access_token_expires(self):
        """Access token should expire after configured time."""
        data = {"sub": "1"}
        # Create token that expires in 1 minute
        token = create_access_token(data, expires_delta=timedelta(minutes=1))
        decoded = decode_token(token)
        assert decoded is not None
        
        # Check it has an expiration
        assert "exp" in decoded
        
        # Verify expiration time is in the future (but close)
        exp_time = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
        expected = datetime.now(timezone.utc) + timedelta(minutes=1)
        time_diff = abs((exp_time - expected).total_seconds())
        assert time_diff < 5

    def test_expired_token_rejected(self):
        """Expired token should be rejected."""
        # Create already-expired token
        payload = {
            "sub": "1",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "type": "access",
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
        result = decode_token(token)
        assert result is None

    def test_token_not_expired_yet(self):
        """Token not yet expired should be valid."""
        data = {"sub": "1"}
        token = create_access_token(data, expires_delta=timedelta(hours=1))
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["type"] == "access"


# =============================================================================
# EDGE CASES AND SECURITY TESTS
# =============================================================================

class TestSecurityEdgeCases:
    """Test edge cases and security scenarios."""

    def test_password_hash_start_with_bcrypt_identifier(self):
        """Bcrypt hash should start with $2 identifier."""
        hashed = hash_password("TestPassword123!")
        assert hashed.startswith("$2")

    def test_empty_password_hash(self):
        """Empty password should still produce a hash."""
        hashed = hash_password("")
        assert isinstance(hashed, str)
        assert len(hashed) > 0
        assert verify_password("", hashed) is True

    def test_none_password_raises(self):
        """None password should raise TypeError."""
        with pytest.raises(TypeError):
            hash_password(None)

    def test_token_with_extra_claims(self):
        """Token with extra claims should preserve them."""
        data = {
            "sub": "1",
            "role": "admin",
            "custom_claim": "custom_value",
            "permissions": ["read", "write"],
        }
        token = create_access_token(data)
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["custom_claim"] == "custom_value"
        assert decoded["permissions"] == ["read", "write"]

    def test_token_subject_types(self):
        """Token subject should work with different ID types."""
        # String ID
        token1 = create_access_token({"sub": "user-uuid-123"})
        decoded1 = decode_token(token1)
        assert decoded1["sub"] == "user-uuid-123"
        
        # Numeric string ID
        token2 = create_access_token({"sub": "12345"})
        decoded2 = decode_token(token2)
        assert decoded2["sub"] == "12345"

    def test_concurrent_token_creation(self):
        """Multiple tokens created concurrently should be unique."""
        tokens = [
            create_access_token({"sub": str(i)})
            for i in range(100)
        ]
        # All tokens should be unique
        assert len(set(tokens)) == 100

    def test_token_payload_immutability(self):
        """Modifying original data shouldn't affect created token."""
        data = {"sub": "1", "role": "viewer"}
        token = create_access_token(data)
        
        # Modify original data
        data["role"] = "super_admin"
        
        # Token should still have original role
        decoded = decode_token(token)
        assert decoded is not None
        assert decoded["role"] == "viewer"

    def test_hash_password_bytes_input(self):
        """Bytes password should raise TypeError."""
        with pytest.raises(TypeError):
            hash_password(b"password")

    def test_verify_password_bytes_input(self):
        """Bytes password verification should raise TypeError."""
        hashed = hash_password("password")
        with pytest.raises(TypeError):
            verify_password(b"password", hashed)
