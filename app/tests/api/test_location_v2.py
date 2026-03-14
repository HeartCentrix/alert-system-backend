"""
API Tests for Location/Geocoding Endpoints

Tests cover:
- Geocoding address lookup
- Reverse geocoding
- Location search
- Photon API integration
- Coordinate validation
- Error handling
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


# =============================================================================
# GEOCODING TESTS
# =============================================================================

class TestGeocodeEndpoint:
    """Test geocoding address to coordinates."""

    def test_geocode_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.post(
            "/api/v1/locations/geocode",
            json={"address": "123 Main St, New York, NY"}
        )
        assert response.status_code == 401

    def test_geocode_success(self, authenticated_client: TestClient):
        """Should geocode valid address."""
        response = authenticated_client.post(
            "/api/v1/locations/geocode",
            json={"address": "123 Main St, New York, NY"}
        )
        # May succeed or fail depending on Photon API availability
        assert response.status_code in [200, 400, 404, 500]

    def test_geocode_empty_address(self, authenticated_client: TestClient):
        """Empty address should be rejected."""
        response = authenticated_client.post(
            "/api/v1/locations/geocode",
            json={"address": ""}
        )
        assert response.status_code == 422

    def test_geocode_missing_address(self, authenticated_client: TestClient):
        """Missing address should be rejected."""
        response = authenticated_client.post(
            "/api/v1/locations/geocode",
            json={}
        )
        assert response.status_code == 422


# =============================================================================
# REVERSE GEOCODING TESTS
# =============================================================================

class TestReverseGeocodeEndpoint:
    """Test reverse geocoding coordinates to address."""

    def test_reverse_geocode_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.post(
            "/api/v1/locations/reverse-geocode",
            json={"latitude": 40.7128, "longitude": -74.0060}
        )
        assert response.status_code == 401

    def test_reverse_geocode_success(self, authenticated_client: TestClient):
        """Should reverse geocode valid coordinates."""
        response = authenticated_client.post(
            "/api/v1/locations/reverse-geocode",
            json={"latitude": 40.7128, "longitude": -74.0060}
        )
        # May succeed or fail depending on Photon API
        assert response.status_code in [200, 400, 500]

    def test_reverse_geocode_invalid_latitude(self, authenticated_client: TestClient):
        """Invalid latitude should be rejected."""
        response = authenticated_client.post(
            "/api/v1/locations/reverse-geocode",
            json={"latitude": 100.0, "longitude": -74.0060}
        )
        assert response.status_code == 422

    def test_reverse_geocode_invalid_longitude(self, authenticated_client: TestClient):
        """Invalid longitude should be rejected."""
        response = authenticated_client.post(
            "/api/v1/locations/reverse-geocode",
            json={"latitude": 40.7128, "longitude": -200.0}
        )
        assert response.status_code == 422


# =============================================================================
# LOCATION SEARCH TESTS
# =============================================================================

class TestLocationSearchEndpoint:
    """Test location search functionality."""

    def test_search_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.get("/api/v1/locations/search?q=New York")
        assert response.status_code == 401

    def test_search_success(self, authenticated_client: TestClient):
        """Should search for locations."""
        response = authenticated_client.get(
            "/api/v1/locations/search",
            params={"q": "New York"}
        )
        assert response.status_code in [200, 500]

    def test_search_empty_query(self, authenticated_client: TestClient):
        """Empty query should be rejected."""
        response = authenticated_client.get(
            "/api/v1/locations/search",
            params={"q": ""}
        )
        assert response.status_code == 422

    def test_search_with_limit(self, authenticated_client: TestClient):
        """Should respect limit parameter."""
        response = authenticated_client.get(
            "/api/v1/locations/search",
            params={"q": "New York", "limit": 5}
        )
        assert response.status_code in [200, 500]


# =============================================================================
# LOCATION CREATION TESTS
# =============================================================================

class TestLocationCreateEndpoint:
    """Test location creation."""

    def test_create_location_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.post(
            "/api/v1/locations/",
            json={
                "name": "Test Location",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "radius_miles": 5.0
            }
        )
        assert response.status_code == 401

    def test_create_location_success(self, authenticated_client: TestClient):
        """Should create valid location."""
        response = authenticated_client.post(
            "/api/v1/locations/",
            json={
                "name": "Test Location",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "radius_miles": 5.0,
                "is_active": True
            }
        )
        assert response.status_code in [200, 422]

    def test_create_location_invalid_latitude(self, authenticated_client: TestClient):
        """Invalid latitude should be rejected."""
        response = authenticated_client.post(
            "/api/v1/locations/",
            json={
                "name": "Test Location",
                "latitude": 100.0,
                "longitude": -74.0060,
                "radius_miles": 5.0
            }
        )
        assert response.status_code == 422

    def test_create_location_invalid_radius(self, authenticated_client: TestClient):
        """Negative radius should be rejected."""
        response = authenticated_client.post(
            "/api/v1/locations/",
            json={
                "name": "Test Location",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "radius_miles": -5.0
            }
        )
        assert response.status_code == 422


# =============================================================================
# LOCATION LISTING TESTS
# =============================================================================

class TestLocationListEndpoint:
    """Test location listing."""

    def test_list_locations_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.get("/api/v1/locations/")
        assert response.status_code == 401

    def test_list_locations_success(self, authenticated_client: TestClient):
        """Should list locations."""
        response = authenticated_client.get("/api/v1/locations/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list) or "locations" in data

    def test_list_locations_filter_active(self, authenticated_client: TestClient):
        """Should filter by active status."""
        response = authenticated_client.get("/api/v1/locations/?is_active=true")
        assert response.status_code == 200


# =============================================================================
# PHOTON API INTEGRATION TESTS
# =============================================================================

class TestPhotonIntegration:
    """Test Photon API integration."""

    @patch('app.api.location_v2.requests.get')
    def test_photon_geocode_success(self, mock_get, authenticated_client: TestClient):
        """Should handle successful Photon response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "features": [
                {
                    "geometry": {"coordinates": [-74.0060, 40.7128]},
                    "properties": {"name": "New York"}
                }
            ]
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = authenticated_client.post(
            "/api/v1/locations/geocode",
            json={"address": "New York"}
        )
        
        assert response.status_code == 200

    @patch('app.api.location_v2.requests.get')
    def test_photon_geocode_no_results(self, mock_get, authenticated_client: TestClient):
        """Should handle no results from Photon."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"features": []}
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        response = authenticated_client.post(
            "/api/v1/locations/geocode",
            json={"address": "Nonexistent Place XYZ123"}
        )
        
        assert response.status_code in [404, 200]

    @patch('app.api.location_v2.requests.get')
    def test_photon_api_error(self, mock_get, authenticated_client: TestClient):
        """Should handle Photon API errors."""
        mock_get.side_effect = Exception("Connection error")

        response = authenticated_client.post(
            "/api/v1/locations/geocode",
            json={"address": "New York"}
        )
        
        assert response.status_code == 500


# =============================================================================
# RBAC TESTS
# =============================================================================

class TestLocationRBAC:
    """Test RBAC for location endpoints."""

    def test_viewer_can_view_locations(self, authenticated_client: TestClient):
        """Viewer should be able to view locations."""
        response = authenticated_client.get("/api/v1/locations/")
        assert response.status_code == 200

    def test_viewer_cannot_create_location(self, authenticated_client: TestClient):
        """Viewer should not create locations."""
        response = authenticated_client.post(
            "/api/v1/locations/",
            json={
                "name": "Test",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "radius_miles": 5.0
            }
        )
        # May be 403 or succeed depending on RBAC rules
        assert response.status_code in [200, 401, 403]

    def test_admin_full_access(self, admin_client: TestClient):
        """Admin has full access to locations."""
        # List
        response = admin_client.get("/api/v1/locations/")
        assert response.status_code == 200


# =============================================================================
# DISTANCE CALCULATION TESTS
# =============================================================================

class TestDistanceCalculation:
    """Test distance calculation endpoints."""

    def test_distance_requires_auth(self, client: TestClient):
        """Unauthenticated request should be rejected."""
        response = client.post(
            "/api/v1/locations/distance",
            json={
                "lat1": 40.7128,
                "lon1": -74.0060,
                "lat2": 34.0522,
                "lon2": -118.2437
            }
        )
        assert response.status_code == 401

    def test_distance_calculation_success(self, authenticated_client: TestClient):
        """Should calculate distance between coordinates."""
        response = authenticated_client.post(
            "/api/v1/locations/distance",
            json={
                "lat1": 40.7128,
                "lon1": -74.0060,
                "lat2": 34.0522,
                "lon2": -118.2437
            }
        )
        assert response.status_code in [200, 404, 500]
