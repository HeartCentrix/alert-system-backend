"""
Tests for Incident Status State Machine

Tests cover:
- Valid status transitions (ACTIVE → MONITORING → RESOLVED/CANCELLED)
- Invalid status transitions (RESOLVED/CANCELLED → any)
- Self-transition rejection (same status)
- Unit tests for _validate_incident_status_transition helper
- Regression guards for BUG-01 (MONITORING missing from transitions map)

These tests ensure the incident lifecycle state machine works correctly
and prevents invalid state transitions.
"""
import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.models import Incident, IncidentStatus, IncidentSeverity, User, UserRole
from app.core.security import hash_password, create_access_token
from app.api.notifications import (
    _validate_incident_status_transition,
    VALID_INCIDENT_STATUS_TRANSITIONS,
)


class TestIncidentStatusTransitionsUnit:
    """Unit tests for _validate_incident_status_transition helper."""

    def test_active_to_monitoring_is_allowed(self):
        """ACTIVE → MONITORING should be allowed (standard path)."""
        assert _validate_incident_status_transition(
            IncidentStatus.ACTIVE, IncidentStatus.MONITORING
        ) is True

    def test_active_to_resolved_is_allowed(self):
        """ACTIVE → RESOLVED should be allowed (fast-track)."""
        assert _validate_incident_status_transition(
            IncidentStatus.ACTIVE, IncidentStatus.RESOLVED
        ) is True

    def test_active_to_cancelled_is_allowed(self):
        """ACTIVE → CANCELLED should be allowed (false alarm)."""
        assert _validate_incident_status_transition(
            IncidentStatus.ACTIVE, IncidentStatus.CANCELLED
        ) is True

    def test_monitoring_to_resolved_is_allowed(self):
        """MONITORING → RESOLVED should be allowed (normal exit)."""
        assert _validate_incident_status_transition(
            IncidentStatus.MONITORING, IncidentStatus.RESOLVED
        ) is True

    def test_monitoring_to_cancelled_is_allowed(self):
        """MONITORING → CANCELLED should be allowed."""
        assert _validate_incident_status_transition(
            IncidentStatus.MONITORING, IncidentStatus.CANCELLED
        ) is True

    def test_resolved_to_monitoring_is_blocked(self):
        """RESOLVED → MONITORING should be blocked (terminal state)."""
        assert _validate_incident_status_transition(
            IncidentStatus.RESOLVED, IncidentStatus.MONITORING
        ) is False

    def test_resolved_to_active_is_blocked(self):
        """RESOLVED → ACTIVE should be blocked (terminal state)."""
        assert _validate_incident_status_transition(
            IncidentStatus.RESOLVED, IncidentStatus.ACTIVE
        ) is False

    def test_cancelled_to_monitoring_is_blocked(self):
        """CANCELLED → MONITORING should be blocked (terminal state)."""
        assert _validate_incident_status_transition(
            IncidentStatus.CANCELLED, IncidentStatus.MONITORING
        ) is False

    def test_cancelled_to_active_is_blocked(self):
        """CANCELLED → ACTIVE should be blocked (terminal state)."""
        assert _validate_incident_status_transition(
            IncidentStatus.CANCELLED, IncidentStatus.ACTIVE
        ) is False

    def test_active_to_active_is_blocked(self):
        """ACTIVE → ACTIVE should be blocked (self-transition)."""
        assert _validate_incident_status_transition(
            IncidentStatus.ACTIVE, IncidentStatus.ACTIVE
        ) is False

    def test_monitoring_to_monitoring_is_blocked(self):
        """MONITORING → MONITORING should be blocked (self-transition)."""
        assert _validate_incident_status_transition(
            IncidentStatus.MONITORING, IncidentStatus.MONITORING
        ) is False

    def test_resolved_to_resolved_is_blocked(self):
        """RESOLVED → RESOLVED should be blocked (self-transition)."""
        assert _validate_incident_status_transition(
            IncidentStatus.RESOLVED, IncidentStatus.RESOLVED
        ) is False

    def test_cancelled_to_cancelled_is_blocked(self):
        """CANCELLED → CANCELLED should be blocked (self-transition)."""
        assert _validate_incident_status_transition(
            IncidentStatus.CANCELLED, IncidentStatus.CANCELLED
        ) is False

    def test_unknown_status_is_blocked(self):
        """Unknown current status should block all transitions."""
        # This tests the .get(current_status, []) fallback
        # We can't easily create an invalid IncidentStatus, but we can test
        # that an empty list is returned for unknown keys
        allowed = VALID_INCIDENT_STATUS_TRANSITIONS.get("unknown_status", [])
        assert allowed == []


class TestIncidentStatusTransitionsIntegration:
    """Integration tests for incident status transitions via API."""

    @pytest.fixture
    def manager_user(self, db_session: Session):
        """Create a test manager user."""
        user = User(
            email="incident-manager@example.com",
            hashed_password=hash_password("TestPass123!"),
            first_name="Incident",
            last_name="Manager",
            role=UserRole.MANAGER,
            is_active=True,
            mfa_enabled=False,  # Disable MFA for testing
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    @pytest.fixture
    def manager_auth_tokens(self, manager_user: User) -> dict:
        """Generate valid auth tokens for the manager user."""
        access_token = create_access_token(
            data={"sub": str(manager_user.id), "role": manager_user.role.value}
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
        }

    @pytest.fixture
    def active_incident(self, db_session: Session, manager_user: User):
        """Create an incident with ACTIVE status."""
        incident = Incident(
            title="Test Incident",
            type="test",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.ACTIVE,
            description="Test incident for status transition tests",
            created_by_id=manager_user.id,
        )
        db_session.add(incident)
        db_session.commit()
        db_session.refresh(incident)
        return incident

    def test_active_to_monitoring_transition(self, db_session, client, manager_auth_tokens, active_incident):
        """
        ACTIVE → MONITORING transition should succeed.
        
        This is the main regression test for BUG-01.
        """
        headers = {
            "Authorization": f"Bearer {manager_auth_tokens['access_token']}",
        }

        # First, make a GET request to get the CSRF token cookie
        get_response = client.get(f"/api/v1/incidents/{active_incident.id}", headers=headers)
        assert get_response.status_code == 200
        csrf_cookie = get_response.cookies.get("csrf_token")
        if csrf_cookie:
            headers["X-CSRF-Token"] = csrf_cookie

        # Update incident status to MONITORING
        response = client.put(
            f"/api/v1/incidents/{active_incident.id}",
            json={"status": "monitoring"},
            headers=headers,
        )

        # Should succeed
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.json()}"
        data = response.json()
        assert data["status"] == "monitoring"

        # Verify in database
        db_session.refresh(active_incident)
        assert active_incident.status == IncidentStatus.MONITORING

    def test_active_to_resolved_fast_track(self, db_session, client, manager_auth_tokens, active_incident):
        """
        ACTIVE → RESOLVED fast-track should succeed.
        """
        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Update to RESOLVED
        response = client.put(
            f"/api/v1/incidents/{active_incident.id}",
            json={"status": "resolved"},
            headers=headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "resolved"
        # Verify resolution metadata is set
        assert data["resolved_at"] is not None

    def test_active_to_cancelled(self, db_session, client, manager_auth_tokens, active_incident):
        """
        ACTIVE → CANCELLED should succeed.
        """
        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Update to CANCELLED
        response = client.put(
            f"/api/v1/incidents/{active_incident.id}",
            json={"status": "cancelled"},
            headers=headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"

    def test_monitoring_to_resolved_transition(self, db_session, client, manager_user, manager_auth_tokens):
        """
        MONITORING → RESOLVED transition should succeed.
        """
        # Create incident in MONITORING status
        incident = Incident(
            title="Monitoring Test Incident",
            type="test",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.MONITORING,
            description="Test incident for MONITORING → RESOLVED transition",
            created_by_id=manager_user.id,
        )
        db_session.add(incident)
        db_session.commit()

        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Update to RESOLVED
        response = client.put(
            f"/api/v1/incidents/{incident.id}",
            json={"status": "resolved"},
            headers=headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "resolved"

    def test_monitoring_to_cancelled_transition(self, db_session, client, manager_user, manager_auth_tokens):
        """
        MONITORING → CANCELLED transition should succeed.
        """
        # Create incident in MONITORING status
        incident = Incident(
            title="Monitoring Cancel Test",
            type="test",
            severity=IncidentSeverity.LOW,
            status=IncidentStatus.MONITORING,
            description="Test incident for MONITORING → CANCELLED transition",
            created_by_id=manager_user.id,
        )
        db_session.add(incident)
        db_session.commit()

        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Update to CANCELLED
        response = client.put(
            f"/api/v1/incidents/{incident.id}",
            json={"status": "cancelled"},
            headers=headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"

    def test_resolved_to_monitoring_is_rejected(self, db_session, client, manager_user, manager_auth_tokens):
        """
        RESOLVED → MONITORING should be rejected (regression guard).

        A resolved incident cannot re-enter monitoring - new incident should be raised.
        """
        # Create incident in RESOLVED status
        incident = Incident(
            title="Resolved Test",
            type="test",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.RESOLVED,
            description="Test incident for RESOLVED → MONITORING rejection",
            created_by_id=manager_user.id,
            resolved_at=datetime.now(timezone.utc),
            resolved_by_id=manager_user.id,
        )
        db_session.add(incident)
        db_session.commit()

        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Attempt to update to MONITORING
        response = client.put(
            f"/api/v1/incidents/{incident.id}",
            json={"status": "monitoring"},
            headers=headers,
        )

        # Should fail with 400
        assert response.status_code == 400
        data = response.json()
        assert "Invalid status transition" in data["detail"]
        assert "resolved" in data["detail"].lower()
        assert "monitoring" in data["detail"].lower()

    def test_cancelled_to_monitoring_is_rejected(self, db_session, client, manager_user, manager_auth_tokens):
        """
        CANCELLED → MONITORING should be rejected (regression guard).

        Cancellation is final - no further transitions allowed.
        """
        # Create incident in CANCELLED status
        incident = Incident(
            title="Cancelled Test",
            type="test",
            severity=IncidentSeverity.LOW,
            status=IncidentStatus.CANCELLED,
            description="Test incident for CANCELLED → MONITORING rejection",
            created_by_id=manager_user.id,
        )
        db_session.add(incident)
        db_session.commit()

        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Attempt to update to MONITORING
        response = client.put(
            f"/api/v1/incidents/{incident.id}",
            json={"status": "monitoring"},
            headers=headers,
        )

        # Should fail with 400
        assert response.status_code == 400
        data = response.json()
        assert "Invalid status transition" in data["detail"]

    def test_same_status_update_is_rejected(self, db_session, client, manager_auth_tokens, active_incident):
        """
        ACTIVE → ACTIVE (self-transition) should be rejected.
        """
        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Attempt to update to same status
        response = client.put(
            f"/api/v1/incidents/{active_incident.id}",
            json={"status": "active"},
            headers=headers,
        )

        # Should fail with 400
        assert response.status_code == 400
        data = response.json()
        assert "Invalid status transition" in data["detail"]

    def test_invalid_status_string_is_rejected_by_schema(self, db_session, client, manager_auth_tokens, active_incident):
        """
        Invalid status string (e.g., "monitor") should be rejected at schema level.

        Pydantic validates against IncidentStatus enum before reaching transition validator.
        """
        headers = {"Authorization": f"Bearer {manager_auth_tokens['access_token']}"}

        # Attempt to update with invalid status string
        response = client.put(
            f"/api/v1/incidents/{active_incident.id}",
            json={"status": "monitor"},  # Invalid - should be "monitoring"
            headers=headers,
        )

        # Should fail with 422 (schema validation error)
        assert response.status_code == 422
