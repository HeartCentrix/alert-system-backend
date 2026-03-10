"""
Tests for MFA Lifecycle Management

Tests cover:
- MFA enrollment flow (start/complete)
- MFA disable flow with policy enforcement
- MFA reset/replace flow
- Recovery code regeneration
- Admin MFA management
- Privileged user restrictions
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models import User, UserRole
from app.core.security import hash_password, verify_totp_code, generate_mfa_secret

client = TestClient(app)


@pytest.fixture
def normal_user(db_session: Session):
    """Create a normal user (VIEWER role) for testing."""
    user = User(
        email="testviewer@example.com",
        hashed_password=hash_password("TestPass123!"),
        first_name="Test",
        last_name="Viewer",
        role=UserRole.VIEWER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_user(db_session: Session):
    """Create an admin user for testing."""
    user = User(
        email="testadmin@example.com",
        hashed_password=hash_password("TestPass123!"),
        first_name="Test",
        last_name="Admin",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def auth_token(normal_user):
    """Get auth token for normal user."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "testviewer@example.com", "password": "TestPass123!"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def admin_token(admin_user):
    """Get auth token for admin user."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "testadmin@example.com", "password": "TestPass123!"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def get_headers(token):
    """Helper to get auth headers."""
    return {"Authorization": f"Bearer {token}"}


class TestMFAEnrollment:
    """Test MFA enrollment flow."""

    def test_start_enrollment_requires_auth(self):
        """Unauthenticated users cannot start enrollment."""
        response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"}
        )
        assert response.status_code == 401

    def test_start_enrollment_with_wrong_password(self, auth_token):
        """Wrong password should fail."""
        response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "WrongPassword"},
            headers=get_headers(auth_token)
        )
        assert response.status_code == 401

    def test_start_enrollment_success(self, auth_token):
        """Valid password should start enrollment."""
        response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"},
            headers=get_headers(auth_token)
        )
        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "qr_code_uri" in data
        assert "manual_entry_key" in data

    def test_complete_enrollment_with_invalid_code(self, auth_token):
        """Invalid OTP code should fail."""
        # First start enrollment
        client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"},
            headers=get_headers(auth_token)
        )

        # Try to complete with invalid code
        response = client.post(
            "/api/v1/account/mfa/enroll/complete",
            json={"code": "000000"},  # Invalid code
            headers=get_headers(auth_token)
        )
        assert response.status_code == 400

    def test_complete_enrollment_success(self, auth_token, db_session: Session):
        """Valid OTP code should complete enrollment."""
        # Start enrollment
        start_response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"},
            headers=get_headers(auth_token)
        )
        secret = start_response.json()["secret"]

        # Generate valid TOTP code
        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Complete enrollment
        response = client.post(
            "/api/v1/account/mfa/enroll/complete",
            json={"code": code},
            headers=get_headers(auth_token)
        )
        assert response.status_code == 200
        data = response.json()
        assert "recovery_codes" in data
        assert len(data["recovery_codes"]) == 10

        # Verify user has MFA enabled
        user = db_session.query(User).filter(User.email == "testviewer@example.com").first()
        assert user.mfa_enabled is True
        assert user.mfa_secret is not None


class TestMFADisable:
    """Test MFA disable flow."""

    def test_disable_mfa_for_privileged_user_blocked(self, admin_token):
        """Admin users cannot self-disable MFA."""
        # First enable MFA for admin
        response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"},
            headers=get_headers(admin_token)
        )
        secret = response.json()["secret"]

        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()

        client.post(
            "/api/v1/account/mfa/enroll/complete",
            json={"code": code},
            headers=get_headers(admin_token)
        )

        # Try to disable - should be blocked
        response = client.post(
            "/api/v1/account/mfa/disable",
            json={"current_password": "TestPass123!", "mfa_code": totp.now()},
            headers=get_headers(admin_token)
        )
        assert response.status_code == 403

    def test_disable_mfa_normal_user_success(self, auth_token, db_session: Session):
        """Normal users can disable MFA."""
        # Enable MFA first
        start_response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"},
            headers=get_headers(auth_token)
        )
        secret = start_response.json()["secret"]

        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()

        client.post(
            "/api/v1/account/mfa/enroll/complete",
            json={"code": code},
            headers=get_headers(auth_token)
        )

        # Disable MFA
        response = client.post(
            "/api/v1/account/mfa/disable",
            json={"current_password": "TestPass123!", "mfa_code": totp.now()},
            headers=get_headers(auth_token)
        )
        assert response.status_code == 200

        # Verify MFA is disabled
        user = db_session.query(User).filter(User.email == "testviewer@example.com").first()
        assert user.mfa_enabled is False
        assert user.mfa_secret is None


class TestMFAReset:
    """Test MFA reset/replace flow."""

    def test_reset_mfa_success(self, auth_token, db_session: Session):
        """Users can reset their MFA."""
        # Enable MFA first
        start_response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"},
            headers=get_headers(auth_token)
        )
        old_secret = start_response.json()["secret"]

        import pyotp
        totp = pyotp.TOTP(old_secret)
        code = totp.now()

        client.post(
            "/api/v1/account/mfa/enroll/complete",
            json={"code": code},
            headers=get_headers(auth_token)
        )

        # Start reset
        reset_start = client.post(
            "/api/v1/account/mfa/reset/start",
            json={"current_password": "TestPass123!", "mfa_code": totp.now()},
            headers=get_headers(auth_token)
        )
        assert reset_start.status_code == 200
        new_secret = reset_start.json()["secret"]

        # Complete reset with new code
        new_totp = pyotp.TOTP(new_secret)
        new_code = new_totp.now()

        reset_complete = client.post(
            "/api/v1/account/mfa/reset/complete",
            json={"code": new_code},
            headers=get_headers(auth_token)
        )
        assert reset_complete.status_code == 200

        # Verify new MFA is enabled
        user = db_session.query(User).filter(User.email == "testviewer@example.com").first()
        assert user.mfa_enabled is True
        assert user.mfa_secret == new_secret
        assert user.mfa_secret != old_secret


class TestMFAStatus:
    """Test MFA status endpoint."""

    def test_get_mfa_status(self, auth_token):
        """Get MFA status for authenticated user."""
        response = client.get(
            "/api/v1/auth/mfa/status",
            headers=get_headers(auth_token)
        )
        assert response.status_code == 200
        data = response.json()
        assert "mfa_enabled" in data
        assert "mfa_required" in data
        assert "can_disable" in data
        assert "recovery_codes_count" in data


class TestAdminMFAManagement:
    """Test admin MFA management endpoints."""

    def test_admin_view_user_mfa_status(self, admin_token, normal_user):
        """Admin can view user MFA status."""
        response = client.get(
            f"/api/v1/users/{normal_user.id}/mfa/status",
            headers=get_headers(admin_token)
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == normal_user.id
        assert "mfa_enabled" in data

    def test_admin_reset_user_mfa(self, admin_token, normal_user, db_session: Session):
        """Admin can reset user MFA."""
        response = client.post(
            f"/api/v1/users/{normal_user.id}/mfa/reset",
            json={"reason": "User lost device"},
            headers=get_headers(admin_token)
        )
        assert response.status_code == 200

        # Verify user's MFA was reset
        user = db_session.query(User).filter(User.id == normal_user.id).first()
        assert user.mfa_enabled is False
        assert user.mfa_secret is not None  # Pending enrollment

    def test_admin_cannot_reset_super_admin_mfa(self, admin_token, db_session: Session):
        """Admin cannot reset SUPER_ADMIN MFA."""
        # Create SUPER_ADMIN user
        super_admin = User(
            email="superadmin@example.com",
            hashed_password=hash_password("TestPass123!"),
            first_name="Super",
            last_name="Admin",
            role=UserRole.SUPER_ADMIN,
            is_active=True,
        )
        db_session.add(super_admin)
        db_session.commit()
        db_session.refresh(super_admin)

        response = client.post(
            f"/api/v1/users/{super_admin.id}/mfa/reset",
            json={"reason": "Test"},
            headers=get_headers(admin_token)
        )
        assert response.status_code == 403


class TestRecoveryCodeRegeneration:
    """Test recovery code regeneration."""

    def test_regenerate_recovery_codes(self, auth_token):
        """Users can regenerate recovery codes."""
        # Enable MFA first
        start_response = client.post(
            "/api/v1/account/mfa/enroll/start",
            json={"current_password": "TestPass123!"},
            headers=get_headers(auth_token)
        )
        secret = start_response.json()["secret"]

        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()

        client.post(
            "/api/v1/account/mfa/enroll/complete",
            json={"code": code},
            headers=get_headers(auth_token)
        )

        # Regenerate codes
        response = client.post(
            "/api/v1/account/mfa/recovery-codes/regenerate",
            json={"current_password": "TestPass123!"},
            headers=get_headers(auth_token)
        )
        assert response.status_code == 200
        data = response.json()
        assert "recovery_codes" in data
        assert len(data["recovery_codes"]) == 10

    def test_regenerate_with_wrong_password(self, auth_token):
        """Wrong password should fail regeneration."""
        response = client.post(
            "/api/v1/account/mfa/recovery-codes/regenerate",
            json={"current_password": "WrongPassword"},
            headers=get_headers(auth_token)
        )
        assert response.status_code == 401
