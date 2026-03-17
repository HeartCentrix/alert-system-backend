"""
Tests for input validation and error handling.

These tests verify that:
1. Invalid input is properly rejected by backend validation
2. Error responses have consistent structure
3. Field-level validation works correctly
4. Request size limits are enforced
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import get_db
from app.models import User, UserRole
from sqlalchemy.orm import Session
from datetime import datetime, timezone

client = TestClient(app)


# Test fixtures
@pytest.fixture
def test_user(db_session):
    """Create a test user for authentication tests."""
    user = User(
        email="testuser@example.com",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzS3MebAJu",  # "Test@1234"
        first_name="Test",
        last_name="User",
        role=UserRole.VIEWER,
        is_active=True,
        mfa_enabled=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_user(db_session):
    """Create an admin user for privileged tests."""
    user = User(
        email="admin@example.com",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzS3MebAJu",  # "Test@1234"
        first_name="Admin",
        last_name="User",
        role=UserRole.ADMIN,
        is_active=True,
        mfa_enabled=True,
        mfa_secret="JBSWY3DPEHPK3PXP",  # Valid TOTP secret
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ─── MFA CODE VALIDATION TESTS ────────────────────────────────────────────────

class TestMFACodeValidation:
    """Test MFA/TOTP code validation."""

    def test_mfa_code_rejects_non_digits(self, db_session):
        """MFA code must contain only digits."""
        # Try to submit letters in MFA code field
        response = client.post(
            "/api/v1/auth/mfa/enroll/complete",
            json={"code": "abcdef"}
        )
        assert response.status_code == 422  # Validation error
        assert "detail" in response.json()
        
    def test_mfa_code_rejects_wrong_length(self, db_session):
        """MFA code must be exactly 6 digits."""
        # Too short
        response = client.post(
            "/api/v1/auth/mfa/enroll/complete",
            json={"code": "12345"}
        )
        assert response.status_code == 422
        
        # Too long
        response = client.post(
            "/api/v1/auth/mfa/enroll/complete",
            json={"code": "1234567"}
        )
        assert response.status_code == 422
        
    def test_mfa_code_accepts_valid_format(self, db_session):
        """Valid 6-digit code passes format validation."""
        response = client.post(
            "/api/v1/auth/mfa/enroll/complete",
            json={"code": "123456"}
        )
        # Should pass validation (may fail for other reasons like missing session)
        assert response.status_code != 422


# ─── RECOVERY CODE VALIDATION TESTS ───────────────────────────────────────────

class TestRecoveryCodeValidation:
    """Test recovery code validation."""

    def test_recovery_code_rejects_too_short(self, db_session):
        """Recovery code must meet minimum length."""
        response = client.post(
            "/api/v1/auth/mfa/recovery-code/verify",
            json={"challenge_token": "test-token", "recovery_code": "ABC"}
        )
        assert response.status_code == 422
        
    def test_recovery_code_validates_format(self, db_session):
        """Recovery code must be alphanumeric."""
        response = client.post(
            "/api/v1/auth/mfa/recovery-code/verify",
            json={"challenge_token": "test-token", "recovery_code": "ABCD-1234-EFGH-5678"}
        )
        # Should pass format validation
        assert response.status_code != 422


# ─── PASSWORD VALIDATION TESTS ────────────────────────────────────────────────

class TestPasswordValidation:
    """Test password strength validation."""

    def test_password_too_short(self, db_session):
        """Password must meet minimum length."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "short",
                "first_name": "New",
                "last_name": "User"
            }
        )
        assert response.status_code == 422
        
    def test_password_missing_uppercase(self, db_session):
        """Password must contain uppercase letter."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "lowercase123!",
                "first_name": "New",
                "last_name": "User"
            }
        )
        assert response.status_code == 422
        assert "uppercase" in response.json()["detail"][0]["msg"].lower()
        
    def test_password_missing_special_char(self, db_session):
        """Password must contain special character."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "NoSpecial123",
                "first_name": "New",
                "last_name": "User"
            }
        )
        assert response.status_code == 422
        assert "special" in response.json()["detail"][0]["msg"].lower()


# ─── NAME FIELD VALIDATION TESTS ──────────────────────────────────────────────

class TestNameFieldValidation:
    """Test name field validation."""

    def test_first_name_empty(self, db_session):
        """First name cannot be empty."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Test@1234",
                "first_name": "",
                "last_name": "User"
            }
        )
        assert response.status_code == 422
        
    def test_first_name_whitespace_only(self, db_session):
        """First name cannot be whitespace only."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Test@1234",
                "first_name": "   ",
                "last_name": "User"
            }
        )
        assert response.status_code == 422
        
    def test_first_name_too_long(self, db_session):
        """First name must not exceed maximum length."""
        long_name = "A" * 100  # Exceeds 50 char limit
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Test@1234",
                "first_name": long_name,
                "last_name": "User"
            }
        )
        assert response.status_code == 422
        
    def test_first_name_allows_valid_characters(self, db_session):
        """First name allows letters, spaces, hyphens, apostrophes."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Test@1234",
                "first_name": "Mary-Jane O'Connor",
                "last_name": "User"
            }
        )
        # Should pass validation
        assert response.status_code != 422


# ─── PHONE FIELD VALIDATION TESTS ─────────────────────────────────────────────

class TestPhoneFieldValidation:
    """Test phone field validation."""

    def test_phone_allows_valid_format(self, db_session):
        """Phone allows digits, spaces, +, (), -."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Test@1234",
                "first_name": "Test",
                "last_name": "User",
                "phone": "+1 (555) 123-4567"
            }
        )
        # Should pass validation
        assert response.status_code != 422
        
    def test_phone_rejects_letters(self, db_session):
        """Phone should not contain letters."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Test@1234",
                "first_name": "Test",
                "last_name": "User",
                "phone": "555-ABC-1234"
            }
        )
        assert response.status_code == 422


# ─── ERROR RESPONSE FORMAT TESTS ──────────────────────────────────────────────

class TestErrorResponseFormat:
    """Test that error responses have consistent format."""

    def test_validation_error_has_detail(self, db_session):
        """Validation errors should have 'detail' field."""
        response = client.post(
            "/api/v1/auth/mfa/enroll/complete",
            json={"code": "invalid"}
        )
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert isinstance(data["detail"], list)
        
    def test_validation_error_items_have_required_fields(self, db_session):
        """Each validation error should have type, loc, msg."""
        response = client.post(
            "/api/v1/auth/mfa/enroll/complete",
            json={"code": "invalid"}
        )
        error_items = response.json()["detail"]
        for error in error_items:
            assert "type" in error
            assert "loc" in error
            assert "msg" in error


# ─── REQUEST SIZE LIMIT TESTS ─────────────────────────────────────────────────

class TestRequestSizeLimits:
    """Test request size limits."""

    def test_oversized_request_rejected(self, db_session):
        """Requests exceeding size limit should be rejected."""
        # Create a very large payload
        large_name = "A" * (10 * 1024 * 1024)  # 10MB
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Test@1234",
                "first_name": large_name,
                "last_name": "User"
            }
        )
        # Should be rejected with 413 or 422
        assert response.status_code in [413, 422]
