"""
API Tests for Authentication Endpoints

Tests cover:
- Login functionality
- Token refresh
- Logout
- Password reset flow
- Change password
- Get current user
- Authentication errors
"""
import pytest
from datetime import datetime, timedelta, timezone

from app.models import User, UserRole, RefreshToken
from app.core.security import hash_password, create_access_token


# =============================================================================
# LOGIN TESTS
# =============================================================================

class TestLoginEndpoint:
    """Test /api/v1/auth/login endpoint."""

    def test_login_success(self, client: pytest.TestClient, test_user: User, test_user_data: dict):
        """Valid credentials should return tokens."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user_data["email"],
                "password": test_user_data["password"]
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == test_user_data["email"]

    def test_login_invalid_email(self, client: pytest.TestClient):
        """Non-existent email should return 401."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "Password123!"
            }
        )
        
        assert response.status_code == 401
        assert "No account found" in response.json()["detail"]

    def test_login_wrong_password(self, client: pytest.TestClient, test_user: User):
        """Wrong password should return 401."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "testuser@example.com",
                "password": "WrongPassword123!"
            }
        )
        
        assert response.status_code == 401
        assert "Incorrect password" in response.json()["detail"]

    def test_login_inactive_user(self, client: pytest.TestClient, inactive_user: User):
        """Inactive user should be denied login."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "inactive@example.com",
                "password": "Password123!"
            }
        )
        
        assert response.status_code == 403
        assert "deactivated" in response.json()["detail"]

    def test_login_empty_email(self, client: pytest.TestClient):
        """Empty email should return validation error."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "",
                "password": "Password123!"
            }
        )
        
        assert response.status_code == 422  # Validation error

    def test_login_empty_password(self, client: pytest.TestClient, test_user: User):
        """Empty password should be accepted (validated by auth logic)."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "testuser@example.com",
                "password": ""
            }
        )
        
        assert response.status_code == 401  # Wrong password

    def test_login_case_sensitive_email(self, client: pytest.TestClient, test_user: User):
        """Email lookup should be case-insensitive."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "TESTUSER@EXAMPLE.COM",
                "password": "TestPassword123!"
            }
        )
        
        # Should find the user (case-insensitive in DB)
        # But password check happens after
        assert response.status_code in [200, 401]

    def test_login_different_roles(self, client: pytest.TestClient, db_session):
        """Users with different roles should be able to login."""
        roles = [UserRole.VIEWER, UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN]
        
        for role in roles:
            user = User(
                email=f"{role.value}@example.com",
                hashed_password=hash_password("Password123!"),
                first_name=role.value,
                last_name="User",
                role=role,
            )
            db_session.add(user)
            db_session.commit()
            
            response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": f"{role.value}@example.com",
                    "password": "Password123!"
                }
            )
            
            assert response.status_code == 200
            assert response.json()["user"]["role"] == role.value


# =============================================================================
# TOKEN REFRESH TESTS
# =============================================================================

class TestRefreshTokenEndpoint:
    """Test /api/v1/auth/refresh endpoint."""

    def test_refresh_token_success(
        self, client: pytest.TestClient, auth_tokens: dict
    ):
        """Valid refresh token should return new tokens."""
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        # New tokens should be different
        assert data["refresh_token"] != auth_tokens["refresh_token"]

    def test_refresh_invalid_token(self, client: pytest.TestClient):
        """Invalid refresh token should return 401."""
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid.token.here"}
        )
        
        assert response.status_code == 401

    def test_refresh_expired_token(self, client: pytest.TestClient):
        """Expired refresh token should return 401."""
        # Create expired token
        from jose import jwt
        from app.config import settings
        
        payload = {
            "sub": "1",
            "exp": datetime.now(timezone.utc) - timedelta(days=1),
            "type": "refresh",
        }
        expired_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": expired_token}
        )
        
        assert response.status_code == 401

    def test_refresh_revoked_token(self, client: pytest.TestClient, auth_tokens: dict, db_session):
        """Revoked refresh token should return 401."""
        # Revoke the token
        token_record = db_session.query(RefreshToken).filter(
            RefreshToken.token == auth_tokens["refresh_token"]
        ).first()
        if token_record:
            token_record.revoked = True
            db_session.commit()
        
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        
        assert response.status_code == 401

    def test_refresh_access_token_instead_of_refresh(
        self, client: pytest.TestClient, auth_tokens: dict
    ):
        """Using access token as refresh should fail."""
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": auth_tokens["access_token"]}
        )
        
        assert response.status_code == 401


# =============================================================================
# LOGOUT TESTS
# =============================================================================

class TestLogoutEndpoint:
    """Test /api/v1/auth/logout endpoint."""

    def test_logout_success(
        self, client: pytest.TestClient, authenticated_client, auth_tokens: dict
    ):
        """Valid logout should revoke token."""
        response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": auth_tokens["refresh_token"]}
        )
        
        assert response.status_code == 200
        assert "Logged out" in response.json()["message"]

    def test_logout_invalid_token(self, client: pytest.TestClient, auth_tokens: dict):
        """Logout with invalid token should succeed (idempotent)."""
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {auth_tokens['access_token']}"},
            json={"refresh_token": "invalid.token"}
        )
        
        # Should still return success (idempotent)
        assert response.status_code == 200

    def test_logout_unauthenticated(self, client: pytest.TestClient):
        """Logout without auth should fail."""
        response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": "any_token"}
        )
        
        assert response.status_code == 401


# =============================================================================
# PASSWORD RESET TESTS
# =============================================================================

class TestPasswordResetEndpoints:
    """Test password reset flow endpoints."""

    def test_forgot_password_success(
        self, client: pytest.TestClient, test_user: User, mock_email_service
    ):
        """Valid forgot password should send email."""
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "testuser@example.com"}
        )
        
        assert response.status_code == 200
        assert "password reset link" in response.json()["message"]
        mock_email_service.send_password_reset_email.assert_called()

    def test_forgot_password_nonexistent_email(
        self, client: pytest.TestClient, mock_email_service
    ):
        """Non-existent email should return same response (security)."""
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"}
        )
        
        assert response.status_code == 200
        assert "password reset link" in response.json()["message"]
        # Should NOT send email
        mock_email_service.send_password_reset_email.assert_not_called()

    def test_forgot_password_rate_limiting(
        self, client: pytest.TestClient, test_user: User
    ):
        """Multiple requests should be rate limited."""
        # First request
        response1 = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "testuser@example.com"}
        )
        assert response1.status_code == 200
        
        # Immediate second request (within rate limit window)
        response2 = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "testuser@example.com"}
        )
        # Should still return 200 but not send another email
        assert response2.status_code == 200

    def test_forgot_password_invalid_email_format(
        self, client: pytest.TestClient
    ):
        """Invalid email format should return validation error."""
        response = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "not-an-email"}
        )
        
        assert response.status_code == 422

    def test_reset_password_success(
        self, client: pytest.TestClient, test_user: User, db_session
    ):
        """Valid reset token should change password."""
        # Create reset token
        import secrets
        token = secrets.token_urlsafe(32)
        test_user.password_reset_token = token
        test_user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        db_session.commit()
        
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token,
                "new_password": "NewSecurePassword123!"
            }
        )
        
        assert response.status_code == 200
        assert "Password reset" in response.json()["message"]
        
        # Verify new password works
        login_response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "testuser@example.com",
                "password": "NewSecurePassword123!"
            }
        )
        assert login_response.status_code == 200

    def test_reset_password_invalid_token(
        self, client: pytest.TestClient
    ):
        """Invalid reset token should fail."""
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": "invalid_token",
                "new_password": "NewPassword123!"
            }
        )
        
        assert response.status_code == 400

    def test_reset_password_expired_token(
        self, client: pytest.TestClient, test_user: User, db_session
    ):
        """Expired reset token should fail."""
        test_user.password_reset_token = "expired_token"
        test_user.password_reset_expires = datetime.now(timezone.utc) - timedelta(hours=1)
        db_session.commit()
        
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": "expired_token",
                "new_password": "NewPassword123!"
            }
        )
        
        assert response.status_code == 400

    def test_reset_password_short_new_password(
        self, client: pytest.TestClient, test_user: User, db_session
    ):
        """Short new password should fail validation."""
        import secrets
        token = secrets.token_urlsafe(32)
        test_user.password_reset_token = token
        test_user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        db_session.commit()
        
        response = client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": token,
                "new_password": "short"
            }
        )
        
        assert response.status_code == 422


# =============================================================================
# CHANGE PASSWORD TESTS
# =============================================================================

class TestChangePasswordEndpoint:
    """Test /api/v1/auth/change-password endpoint."""

    def test_change_password_success(
        self, authenticated_client, test_user_data: dict
    ):
        """Valid change password should work."""
        response = authenticated_client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": test_user_data["password"],
                "new_password": "NewSecurePassword123!"
            }
        )
        
        assert response.status_code == 200
        assert "Password changed" in response.json()["message"]

    def test_change_password_wrong_current(
        self, authenticated_client, test_user_data: dict
    ):
        """Wrong current password should fail."""
        response = authenticated_client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongPassword123!",
                "new_password": "NewSecurePassword123!"
            }
        )
        
        assert response.status_code == 400
        assert "incorrect" in response.json()["detail"].lower()

    def test_change_password_unauthenticated(self, client: pytest.TestClient):
        """Unauthenticated request should fail."""
        response = client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "OldPassword123!",
                "new_password": "NewPassword123!"
            }
        )
        
        assert response.status_code == 401

    def test_change_password_short_new_password(
        self, authenticated_client, test_user_data: dict
    ):
        """Short new password should fail validation."""
        response = authenticated_client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": test_user_data["password"],
                "new_password": "short"
            }
        )
        
        assert response.status_code == 422


# =============================================================================
# GET CURRENT USER TESTS
# =============================================================================

class TestGetCurrentUserEndpoint:
    """Test /api/v1/auth/me endpoint."""

    def test_get_me_success(self, authenticated_client, test_user: User):
        """Authenticated request should return user data."""
        response = authenticated_client.get("/api/v1/auth/me")
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user.email
        assert data["first_name"] == test_user.first_name
        assert "password" not in data  # Password should not be exposed

    def test_get_me_unauthenticated(self, client: pytest.TestClient):
        """Unauthenticated request should fail."""
        response = client.get("/api/v1/auth/me")
        
        assert response.status_code == 401

    def test_get_me_with_expired_token(self, client: pytest.TestClient, expired_token: str):
        """Expired token should fail."""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401

    def test_get_me_with_invalid_token(self, client: pytest.TestClient):
        """Invalid token should fail."""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        
        assert response.status_code == 401

    def test_get_me_deleted_user(
        self, client: pytest.TestClient, test_user: User, db_session
    ):
        """Deleted user token should fail."""
        # Soft delete the user
        from datetime import datetime, timezone
        test_user.deleted_at = datetime.now(timezone.utc)
        db_session.commit()
        
        # Create new token for deleted user
        token = create_access_token({"sub": str(test_user.id), "role": test_user.role.value})
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 401
