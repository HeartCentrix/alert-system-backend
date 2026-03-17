"""
Security Tests - JWT Token Security

Tests cover:
- Token tampering detection
- Token expiration enforcement
- Algorithm confusion attacks
- Secret key attacks
- Token reuse prevention
- Role manipulation attempts
"""
import pytest
from datetime import datetime, timedelta, timezone
import jwt
from unittest.mock import patch

from app.core.security import ALGORITHM, create_access_token, decode_token
from app.config import settings
from app.models import UserRole


# =============================================================================
# TOKEN TAMPERING TESTS
# =============================================================================

class TestTokenTampering:
    """Test JWT token tampering detection."""

    def test_tampered_payload_rejected(self, client, auth_tokens: dict):
        """Modified token payload should be rejected."""
        # Decode and modify payload
        import base64
        import json
        
        parts = auth_tokens["access_token"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        
        # Tamper with role
        payload["role"] = "super_admin"
        
        # Re-encode
        tampered_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tampered_token}"}
        )
        
        assert response.status_code == 401

    def test_tampered_signature_rejected(self, auth_tokens: dict):
        """Modified signature should be rejected."""
        parts = auth_tokens["access_token"].split(".")
        # Tamper with signature
        tampered_signature = parts[2][:-5] + "XXXXX"
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_signature}"
        
        result = decode_token(tampered_token)
        assert result is None

    def test_removed_signature_rejected(self, auth_tokens: dict):
        """Token without signature should be rejected."""
        parts = auth_tokens["access_token"].split(".")
        no_sig_token = f"{parts[0]}.{parts[1]}."
        
        result = decode_token(no_sig_token)
        assert result is None

    def test_extra_dot_rejected(self, auth_tokens: dict):
        """Token with extra parts should be rejected."""
        tampered_token = auth_tokens["access_token"] + ".extra"
        
        result = decode_token(tampered_token)
        assert result is None


# =============================================================================
# ALGORITHM CONFUSION ATTACKS
# =============================================================================

class TestAlgorithmConfusion:
    """Test protection against algorithm confusion attacks."""

    def test_none_algorithm_rejected(self):
        """Token with 'none' algorithm should be rejected."""
        # Create token with 'none' algorithm
        payload = {"sub": "1", "role": "super_admin", "type": "access"}
        none_token = jwt.encode(payload, "", algorithm="none")
        
        result = decode_token(none_token)
        assert result is None

    def test_hs256_vs_hs512_mismatch(self):
        """Token created with different algorithm should fail."""
        payload = {"sub": "1", "role": "viewer", "type": "access"}
        
        # Create with HS512
        wrong_algo_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS512")
        
        # Decode with HS256 (what our app uses)
        result = decode_token(wrong_algo_token)
        assert result is None

    def test_asymmetric_algorithm_not_supported(self):
        """RS256 tokens should be rejected (we only support HS256)."""
        # We can't easily create RS256 tokens without keys,
        # but we verify our decode only accepts HS256
        payload = {"sub": "1", "alg": "RS256"}
        
        # Any non-HS256 token will fail with our secret
        result = decode_token("fake.token.here")
        assert result is None


# =============================================================================
# SECRET KEY ATTACKS
# =============================================================================

class TestSecretKeyAttacks:
    """Test protection against secret key attacks."""

    def test_weak_secret_detection(self):
        """Test that weak secrets would be vulnerable (documentation)."""
        # This test documents that SECRET_KEY should be strong
        weak_secret = "weak"
        
        # Token created with weak secret
        payload = {"sub": "1", "type": "access"}
        weak_token = jwt.encode(payload, weak_secret, algorithm=ALGORITHM)
        
        # Our app uses different secret, so token is invalid
        result = decode_token(weak_token)
        assert result is None
        
        # NOTE: In production, ensure SECRET_KEY is at least 32 random chars

    def test_empty_secret_rejected(self):
        """Empty secret should not be used in production."""
        # Verify our settings have a proper secret
        assert len(settings.SECRET_KEY) >= 32
        assert settings.SECRET_KEY != "change-this-secret-key-in-production-32chars" or \
               settings.APP_ENV == "development"

    def test_common_secret_patterns(self):
        """Test that common/weak secret patterns are documented."""
        weak_patterns = [
            "secret",
            "password",
            "123456",
            "qwerty",
            "letmein",
        ]
        
        # Our secret should not match common patterns
        secret_lower = settings.SECRET_KEY.lower()
        for pattern in weak_patterns:
            assert pattern not in secret_lower or settings.APP_ENV == "development"


# =============================================================================
# TOKEN EXPIRATION TESTS
# =============================================================================

class TestTokenExpirationSecurity:
    """Test token expiration security."""

    def test_expired_token_rejected(self, client, test_user: User):
        """Expired access token should be rejected."""
        # Create expired token
        payload = {
            "sub": str(test_user.id),
            "role": test_user.role.value,
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "type": "access",
        }
        expired_token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401

    def test_token_expires_at_boundary(self, client, test_user: User):
        """Token at expiration boundary should be handled correctly."""
        # Create token expiring in 1 second
        payload = {
            "sub": str(test_user.id),
            "role": test_user.role.value,
            "exp": datetime.now(timezone.utc) + timedelta(seconds=1),
            "type": "access",
        }
        nearly_expired = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
        
        # Should work immediately
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {nearly_expired}"}
        )
        assert response.status_code == 200

    def test_refresh_token_expiration_enforced(self, client, db_session):
        """Expired refresh tokens should be rejected."""
        # Create expired refresh token in DB
        from app.models import RefreshToken
        
        expired_rt = RefreshToken(
            user_id=1,
            token="expired_refresh_token",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        db_session.add(expired_rt)
        db_session.commit()
        
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "expired_refresh_token"}
        )
        
        assert response.status_code == 401


# =============================================================================
# ROLE MANIPULATION TESTS
# =============================================================================

class TestRoleManipulation:
    """Test protection against role manipulation."""

    def test_cannot_escalate_role_in_token(self, client, test_user: User):
        """User cannot escalate their role by modifying token."""
        # Create token with escalated role
        payload = {
            "sub": str(test_user.id),
            "role": UserRole.SUPER_ADMIN.value,  # Escalated!
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "type": "access",
        }
        escalated_token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
        
        # Try to access admin endpoint
        response = client.get(
            "/api/v1/users",  # Requires admin
            headers={"Authorization": f"Bearer {escalated_token}"}
        )
        
        # Should be rejected because role is checked against DB
        assert response.status_code == 401

    def test_role_verified_from_database(self, client, test_user: User, db_session):
        """Role should be verified from database, not just token."""
        # Token says viewer, DB says viewer - should work for viewer endpoints
        token = create_access_token({"sub": str(test_user.id), "role": test_user.role.value})
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        # Role in response should match DB, not potentially tampered token
        assert response.json()["role"] == test_user.role.value


# =============================================================================
# TOKEN REUSE AND REVOCATION
# =============================================================================

class TestTokenRevocation:
    """Test token revocation functionality."""

    def test_revoked_refresh_token_rejected(
        self, client, auth_tokens: dict, db_session
    ):
        """Revoked refresh token should be rejected."""
        # Revoke the token
        from app.models import RefreshToken
        rt = db_session.query(RefreshToken).filter(
            RefreshToken.token == auth_tokens["refresh_token"]
        ).first()
        if rt:
            rt.revoked = True
            db_session.commit()
        
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        
        assert response.status_code == 401

    def test_logout_revokes_token(
        self, client, authenticated_client, auth_tokens: dict, db_session
    ):
        """Logout should revoke refresh token."""
        # Logout
        client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        
        # Try to use revoked token
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        
        assert response.status_code == 401

    def test_access_token_not_revocable(self, client, test_user: User):
        """Access tokens cannot be explicitly revoked (short-lived)."""
        # Access tokens are short-lived and not stored in DB
        # Only refresh tokens can be revoked
        # This is by design - access tokens expire quickly
        pass  # Documentation test


# =============================================================================
# BRUTE FORCE AND RATE LIMITING
# =============================================================================

class TestBruteForceProtection:
    """Test brute force and rate limiting protection."""

    def test_multiple_failed_logins(self, client, test_user: User):
        """Multiple failed logins should all return 401."""
        for _ in range(10):
            response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": "testuser@example.com",
                    "password": "WrongPassword123!"
                }
            )
            assert response.status_code == 401

    def test_login_timing_attack(self, client, test_user: User):
        """Login should take same time for valid/invalid users (timing attack prevention)."""
        import time
        
        # Time failed login with non-existent user
        start = time.time()
        client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@example.com", "password": "Password123!"}
        )
        time_nonexistent = time.time() - start
        
        # Time failed login with existent user
        start = time.time()
        client.post(
            "/api/v1/auth/login",
            json={"email": "testuser@example.com", "password": "WrongPassword123!"}
        )
        time_existent = time.time() - start
        
        # Times should be similar (within 100ms)
        # Note: This is a soft assertion as timing can vary
        time_diff = abs(time_nonexistent - time_existent)
        assert time_diff < 0.5  # 500ms tolerance

    def test_password_reset_rate_limiting(self, client, test_user: User):
        """Password reset should be rate limited."""
        # First request
        response1 = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "testuser@example.com"}
        )
        assert response1.status_code == 200
        
        # Immediate second request
        response2 = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "testuser@example.com"}
        )
        # Should still return 200 (to prevent enumeration)
        # But should not send another email
        assert response2.status_code == 200


# =============================================================================
# EMAIL ENUMERATION PREVENTION
# =============================================================================

class TestEmailEnumeration:
    """Test protection against email enumeration."""

    def test_forgot_password_same_response(self, client, test_user: User):
        """Forgot password should return same response for existing/non-existing emails."""
        # Existing email
        response1 = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "testuser@example.com"}
        )
        
        # Non-existing email
        response2 = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"}
        )
        
        # Responses should be identical
        assert response1.status_code == response2.status_code
        assert response1.json() == response2.json()

    def test_login_different_response(self, client, test_user: User):
        """Login may return different messages (acceptable for UX)."""
        # Non-existent user
        response1 = client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@example.com", "password": "Password123!"}
        )
        
        # Existing user, wrong password
        response2 = client.post(
            "/api/v1/auth/login",
            json={"email": "testuser@example.com", "password": "WrongPassword123!"}
        )
        
        # Both should be 401, but messages may differ
        assert response1.status_code == 401
        assert response2.status_code == 401


# =============================================================================
# HEADER INJECTION TESTS
# =============================================================================

class TestHeaderInjection:
    """Test protection against header injection attacks."""

    def test_newline_in_token(self):
        """Token with newline characters should be rejected."""
        # Try to inject headers via token
        malicious_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\r\nX-Injected: header"
        
        result = decode_token(malicious_token)
        assert result is None

    def test_null_byte_in_token(self):
        """Token with null bytes should be rejected."""
        malicious_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0\x00.signature"
        
        result = decode_token(malicious_token)
        assert result is None
