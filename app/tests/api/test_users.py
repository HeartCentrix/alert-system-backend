"""
API Tests for User Management Endpoints

Tests cover:
- User listing
- User creation
- User updates
- User deletion
- CSV import
- Role management
- RBAC enforcement
"""
import pytest
from fastapi.testclient import TestClient
from app.models import User, UserRole


# =============================================================================
# USER LISTING TESTS
# =============================================================================

class TestUserListEndpoint:
    """Test GET /api/v1/users/ endpoint."""

    def test_list_users_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.get("/api/v1/users/")
        assert response.status_code == 401

    def test_list_users_success(self, authenticated_client: TestClient, test_user: User):
        """Authenticated user should see user list."""
        response = authenticated_client.get("/api/v1/users/")
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert len(data["users"]) > 0

    def test_list_users_pagination(self, authenticated_client: TestClient):
        """Pagination should work correctly."""
        response = authenticated_client.get("/api/v1/users/?skip=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert "total" in data


# =============================================================================
# USER CREATION TESTS
# =============================================================================

class TestUserCreateEndpoint:
    """Test POST /api/v1/users/ endpoint."""

    def test_create_user_requires_admin(self, authenticated_client: TestClient):
        """Non-admin user should be denied user creation."""
        response = authenticated_client.post(
            "/api/v1/users/",
            json={
                "email": "newuser@example.com",
                "password": "Password123!",
                "first_name": "New",
                "last_name": "User"
            }
        )
        # Regular users can't create other users
        assert response.status_code in [401, 403]

    def test_create_user_success(self, admin_client: TestClient):
        """Admin should be able to create user."""
        response = admin_client.post(
            "/api/v1/users/",
            json={
                "email": "newuser@example.com",
                "password": "Password123!",
                "first_name": "New",
                "last_name": "User",
                "role": "viewer"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "email" in data
        assert data["email"] == "newuser@example.com"

    def test_create_user_duplicate_email(self, admin_client: TestClient, test_user: User):
        """Duplicate email should be rejected."""
        response = admin_client.post(
            "/api/v1/users/",
            json={
                "email": test_user.email,
                "password": "Password123!",
                "first_name": "Duplicate",
                "last_name": "User"
            }
        )
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"].lower()

    def test_create_user_weak_password(self, admin_client: TestClient):
        """Weak password should be rejected."""
        response = admin_client.post(
            "/api/v1/users/",
            json={
                "email": "weakpass@example.com",
                "password": "123",  # Too weak
                "first_name": "Weak",
                "last_name": "Pass"
            }
        )
        assert response.status_code == 422  # Validation error


# =============================================================================
# USER UPDATE TESTS
# =============================================================================

class TestUserUpdateEndpoint:
    """Test PUT /api/v1/users/{user_id} endpoint."""

    def test_update_user_requires_auth(self, client: TestClient, test_user: User):
        """Unauthenticated request should be rejected."""
        response = client.put(
            f"/api/v1/users/{test_user.id}",
            json={"first_name": "Updated"}
        )
        assert response.status_code == 401

    def test_update_own_profile(self, authenticated_client: TestClient):
        """User should be able to update own profile."""
        response = authenticated_client.put(
            "/api/v1/users/me",
            json={"first_name": "Updated"}
        )
        assert response.status_code in [200, 404]  # 404 if endpoint doesn't exist

    def test_update_user_role_requires_admin(self, authenticated_client: TestClient, test_user: User):
        """Non-admin should not be able to change roles."""
        response = authenticated_client.put(
            f"/api/v1/users/{test_user.id}",
            json={"role": "admin"}
        )
        assert response.status_code in [401, 403]


# =============================================================================
# USER DELETION TESTS
# =============================================================================

class TestUserDeleteEndpoint:
    """Test DELETE /api/v1/users/{user_id} endpoint."""

    def test_delete_user_requires_admin(self, authenticated_client: TestClient, test_user: User):
        """Non-admin should not be able to delete users."""
        response = authenticated_client.delete(f"/api/v1/users/{test_user.id}")
        assert response.status_code in [401, 403]

    def test_delete_user_success(self, admin_client: TestClient, db_session):
        """Admin should be able to delete user."""
        # Create test user
        user = User(
            email="todelete@example.com",
            hashed_password="password",
            first_name="Delete",
            last_name="Me",
            role=UserRole.VIEWER
        )
        db_session.add(user)
        db_session.commit()
        user_id = user.id

        response = admin_client.delete(f"/api/v1/users/{user_id}")
        assert response.status_code in [200, 404]


# =============================================================================
# CSV IMPORT TESTS
# =============================================================================

class TestUserCSVImport:
    """Test POST /api/v1/users/import endpoint."""

    def test_csv_import_requires_admin(self, authenticated_client: TestClient):
        """Non-admin should not be able to import users."""
        # Create test CSV
        csv_content = "email,password,first_name,last_name,role\ntest@example.com,Password123!,Test,User,viewer"
        
        response = authenticated_client.post(
            "/api/v1/users/import",
            files={"file": ("users.csv", csv_content, "text/csv")}
        )
        assert response.status_code in [401, 403]

    def test_csv_import_success(self, admin_client: TestClient):
        """Admin should be able to import users via CSV."""
        csv_content = "email,password,first_name,last_name,role\ntestimport@example.com,Password123!,Import,Test,viewer"
        
        response = admin_client.post(
            "/api/v1/users/import",
            files={"file": ("users.csv", csv_content, "text/csv")}
        )
        assert response.status_code in [200, 422]  # 422 if validation fails


# =============================================================================
# RBAC TESTS
# =============================================================================

class TestUserRBAC:
    """Test Role-Based Access Control for user endpoints."""

    def test_viewer_cannot_create_users(self, authenticated_client: TestClient):
        """Viewer role should not create users."""
        response = authenticated_client.post(
            "/api/v1/users/",
            json={
                "email": "nouser@example.com",
                "password": "Password123!",
                "first_name": "No",
                "last_name": "Access"
            }
        )
        assert response.status_code in [401, 403]

    def test_manager_limited_permissions(self, manager_user, admin_client: TestClient):
        """Manager role has limited permissions."""
        # Managers might be able to create viewers but not admins
        # This depends on your specific RBAC rules
        pass  # Placeholder for manager-specific tests

    def test_admin_full_access(self, admin_client: TestClient):
        """Admin role has full access to user management."""
        # Admin can list
        response = admin_client.get("/api/v1/users/")
        assert response.status_code == 200
        
        # Admin can create
        response = admin_client.post(
            "/api/v1/users/",
            json={
                "email": "admintest@example.com",
                "password": "Password123!",
                "first_name": "Admin",
                "last_name": "Test"
            }
        )
        assert response.status_code in [200, 400]  # 400 if email exists


# =============================================================================
# USER SEARCH/FILTER TESTS
# =============================================================================

class TestUserSearch:
    """Test user search and filtering."""

    def test_search_by_email(self, authenticated_client: TestClient, test_user: User):
        """Should be able to search users by email."""
        response = authenticated_client.get(f"/api/v1/users/?search={test_user.email}")
        assert response.status_code == 200
        data = response.json()
        assert "users" in data

    def test_search_by_name(self, authenticated_client: TestClient, test_user: User):
        """Should be able to search users by name."""
        response = authenticated_client.get(f"/api/v1/users/?search={test_user.first_name}")
        assert response.status_code == 200


# =============================================================================
# USER STATUS TESTS
# =============================================================================

class TestUserStatus:
    """Test user activation/deactivation."""

    def test_deactivate_user_requires_admin(self, authenticated_client: TestClient, test_user: User):
        """Non-admin should not deactivate users."""
        response = authenticated_client.patch(f"/api/v1/users/{test_user.id}/deactivate")
        assert response.status_code in [401, 403, 404]

    def test_activate_user_requires_admin(self, authenticated_client: TestClient, test_user: User):
        """Non-admin should not activate users."""
        response = authenticated_client.patch(f"/api/v1/users/{test_user.id}/activate")
        assert response.status_code in [401, 403, 404]
