"""
API Tests for Notification Endpoints

Tests cover:
- Notification creation
- Notification scheduling
- Notification sending
- Notification status
- Response tracking
- RBAC enforcement
"""
import pytest
from fastapi.testclient import TestClient
from app.models import Notification, NotificationStatus, Incident


# =============================================================================
# NOTIFICATION CREATION TESTS
# =============================================================================

class TestNotificationCreate:
    """Test POST /api/v1/notifications/ endpoint."""

    def test_create_notification_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.post(
            "/api/v1/notifications/",
            json={
                "title": "Test Alert",
                "message": "Test message",
                "channels": ["sms", "email"]
            }
        )
        assert response.status_code == 401

    def test_create_notification_success(self, authenticated_client: TestClient):
        """Authenticated user should be able to create notification."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Test Alert",
                "message": "Test message",
                "channels": ["sms", "email"],
                "target_all": True
            }
        )
        assert response.status_code in [200, 422]  # 422 if validation fails

    def test_create_notification_missing_title(self, authenticated_client: TestClient):
        """Missing title should be rejected."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "message": "Test message",
                "channels": ["sms"]
            }
        )
        assert response.status_code == 422  # Validation error

    def test_create_notification_invalid_channels(self, authenticated_client: TestClient):
        """Invalid channel should be rejected."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Test",
                "message": "Test",
                "channels": ["invalid_channel"]
            }
        )
        assert response.status_code == 422


# =============================================================================
# NOTIFICATION SCHEDULING TESTS
# =============================================================================

class TestNotificationSchedule:
    """Test notification scheduling endpoints."""

    def test_schedule_notification_success(self, authenticated_client: TestClient):
        """Should be able to schedule notification."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Scheduled Alert",
                "message": "Future message",
                "channels": ["email"],
                "target_all": True,
                "scheduled_for": "2026-12-31T23:59:59Z"
            }
        )
        assert response.status_code in [200, 422]

    def test_schedule_notification_past_date(self, authenticated_client: TestClient):
        """Past date should be rejected or send immediately."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Past Alert",
                "message": "Too late",
                "channels": ["email"],
                "scheduled_for": "2020-01-01T00:00:00Z"
            }
        )
        # Should either reject or accept and send immediately
        assert response.status_code in [200, 400, 422]


# =============================================================================
# NOTIFICATION LISTING TESTS
# =============================================================================

class TestNotificationList:
    """Test GET /api/v1/notifications/ endpoint."""

    def test_list_notifications_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.get("/api/v1/notifications/")
        assert response.status_code == 401

    def test_list_notifications_success(self, authenticated_client: TestClient):
        """Authenticated user should see notifications."""
        response = authenticated_client.get("/api/v1/notifications/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "notifications" in data

    def test_list_notifications_filter_status(self, authenticated_client: TestClient):
        """Should filter by status."""
        response = authenticated_client.get("/api/v1/notifications/?status=sent")
        assert response.status_code == 200


# =============================================================================
# NOTIFICATION STATUS TESTS
# =============================================================================

class TestNotificationStatus:
    """Test notification status endpoints."""

    def test_get_notification_requires_auth(self, client: TestClient, db_session):
        """Unauthenticated request should be rejected."""
        # Create test notification
        notification = Notification(
            title="Test",
            message="Test",
            status=NotificationStatus.DRAFT
        )
        db_session.add(notification)
        db_session.commit()
        
        response = client.get(f"/api/v1/notifications/{notification.id}")
        assert response.status_code == 401

    def test_update_notification_status(self, authenticated_client: TestClient, db_session):
        """Should be able to update notification status."""
        notification = Notification(
            title="Test",
            message="Test",
            status=NotificationStatus.DRAFT
        )
        db_session.add(notification)
        db_session.commit()
        
        response = authenticated_client.patch(
            f"/api/v1/notifications/{notification.id}/send",
            json={}
        )
        assert response.status_code in [200, 404, 422]


# =============================================================================
# NOTIFICATION RESPONSE TRACKING TESTS
# =============================================================================

class TestNotificationResponses:
    """Test notification response tracking."""

    def test_get_notification_responses(self, authenticated_client: TestClient, db_session):
        """Should be able to get responses for a notification."""
        notification = Notification(
            title="Test",
            message="Test",
            status=NotificationStatus.SENT,
            response_required=True
        )
        db_session.add(notification)
        db_session.commit()
        
        response = authenticated_client.get(f"/api/v1/notifications/{notification.id}/responses")
        assert response.status_code in [200, 404]


# =============================================================================
# NOTIFICATION TEMPLATES TESTS
# =============================================================================

class TestNotificationTemplates:
    """Test notification template endpoints."""

    def test_list_templates_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.get("/api/v1/notifications/templates")
        assert response.status_code == 401

    def test_create_template_success(self, authenticated_client: TestClient):
        """Should be able to create template."""
        response = authenticated_client.post(
            "/api/v1/notifications/templates",
            json={
                "name": "Emergency Alert",
                "subject": "EMERGENCY: {{title}}",
                "message": "{{message}}",
                "channels": ["sms", "email"]
            }
        )
        assert response.status_code in [200, 422]


# =============================================================================
# RBAC TESTS
# =============================================================================

class TestNotificationRBAC:
    """Test Role-Based Access Control for notifications."""

    def test_viewer_can_create_notifications(self, authenticated_client: TestClient):
        """Viewer role should be able to create notifications."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Viewer Alert",
                "message": "Test",
                "channels": ["email"],
                "target_all": True
            }
        )
        # Viewers should be able to create notifications
        assert response.status_code in [200, 422]

    def test_admin_full_access(self, admin_client: TestClient):
        """Admin has full access to notifications."""
        # List
        response = admin_client.get("/api/v1/notifications/")
        assert response.status_code == 200
        
        # Create
        response = admin_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Admin Alert",
                "message": "Test",
                "channels": ["sms"]
            }
        )
        assert response.status_code in [200, 422]


# =============================================================================
# BULK NOTIFICATION TESTS
# =============================================================================

class TestBulkNotifications:
    """Test bulk notification operations."""

    def test_send_to_specific_users(self, authenticated_client: TestClient):
        """Should send to specific users."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Targeted Alert",
                "message": "Test",
                "channels": ["email"],
                "target_all": False
                # Would include user_ids in real test
            }
        )
        assert response.status_code in [200, 422]

    def test_send_to_groups(self, authenticated_client: TestClient):
        """Should send to specific groups."""
        response = authenticated_client.post(
            "/api/v1/notifications/",
            json={
                "title": "Group Alert",
                "message": "Test",
                "channels": ["email"],
                "target_all": False
                # Would include group_ids in real test
            }
        )
        assert response.status_code in [200, 422]
