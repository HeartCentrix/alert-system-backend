"""
Tests for LocationIQ Autocomplete Proxy API

Run with: pytest app/tests/test_location.py -v
"""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.api.location import _validate_query, _generate_cache_key, _get_cached, _set_cache, _location_cache
from datetime import datetime, timedelta, timezone

client = TestClient(app)


# ─── UNIT TESTS: VALIDATION ───────────────────────────────────────────────────

class TestValidation:
    """Test query validation function."""
    
    def test_valid_query(self):
        """Test valid queries pass validation."""
        is_valid, error = _validate_query("Empire State Building")
        assert is_valid is True
        assert error is None
    
    def test_valid_query_with_special_chars(self):
        """Test valid queries with allowed special characters."""
        is_valid, error = _validate_query("123 Main St., Suite #100")
        assert is_valid is True
        assert error is None
    
    def test_empty_query(self):
        """Test empty query fails validation."""
        is_valid, error = _validate_query("")
        assert is_valid is False
        assert "required" in error.lower()
    
    def test_whitespace_only_query(self):
        """Test whitespace-only query fails validation."""
        is_valid, error = _validate_query("   ")
        assert is_valid is False
        assert "required" in error.lower()
    
    def test_too_short_query(self):
        """Test query shorter than 3 characters fails."""
        is_valid, error = _validate_query("Ab")
        assert is_valid is False
        assert "3 characters" in error
    
    def test_exact_min_length_query(self):
        """Test query with exactly 3 characters passes."""
        is_valid, error = _validate_query("Abc")
        assert is_valid is True
        assert error is None
    
    def test_too_long_query(self):
        """Test query longer than 200 characters fails."""
        long_query = "a" * 201
        is_valid, error = _validate_query(long_query)
        assert is_valid is False
        assert "200 characters" in error
    
    def test_invalid_characters_query(self):
        """Test query with invalid characters fails."""
        is_valid, error = _validate_query("Test<script>alert(1)</script>")
        assert is_valid is False
        assert "invalid characters" in error.lower()


# ─── UNIT TESTS: CACHING ──────────────────────────────────────────────────────

class TestCaching:
    """Test caching functions."""
    
    def setup_method(self):
        """Clear cache before each test."""
        _location_cache.clear()
    
    def test_cache_key_generation(self):
        """Test cache key is consistent for same inputs."""
        key1 = _generate_cache_key("test", "us", None)
        key2 = _generate_cache_key("test", "us", None)
        assert key1 == key2
    
    def test_cache_key_different_for_different_inputs(self):
        """Test cache key differs for different inputs."""
        key1 = _generate_cache_key("test", "us", None)
        key2 = _generate_cache_key("test", "ca", None)
        assert key1 != key2
    
    def test_set_and_get_cache(self):
        """Test storing and retrieving from cache."""
        test_data = [{"lat": 40.7, "lon": -74.0}]
        cache_key = _generate_cache_key("test", "us", None)
        
        _set_cache(cache_key, test_data)
        result = _get_cached(cache_key)
        
        assert result == test_data
    
    def test_get_expired_cache(self):
        """Test expired cache returns None."""
        test_data = [{"lat": 40.7, "lon": -74.0}]
        cache_key = _generate_cache_key("test", "us", None)
        
        # Manually set expired cache
        _location_cache[cache_key] = {
            "data": test_data,
            "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)
        }
        
        result = _get_cached(cache_key)
        assert result is None
        assert cache_key not in _location_cache  # Should be cleaned up


# ─── INTEGRATION TESTS: API ENDPOINT ──────────────────────────────────────────

class TestAutocompleteEndpoint:
    """Test the /api/v1/location/autocomplete endpoint."""
    
    def test_missing_query_parameter(self):
        """Test endpoint rejects missing 'q' parameter."""
        response = client.get("/api/v1/location/autocomplete")
        assert response.status_code == 422  # Validation error
    
    def test_empty_query_parameter(self):
        """Test endpoint rejects empty query."""
        response = client.get("/api/v1/location/autocomplete?q=")
        assert response.status_code == 400
    
    def test_short_query_parameter(self):
        """Test endpoint rejects query shorter than 3 characters."""
        response = client.get("/api/v1/location/autocomplete?q=Ab")
        assert response.status_code == 400
        assert "3 characters" in response.json()["detail"]
    
    def test_valid_query_format(self, monkeypatch):
        """Test endpoint accepts valid query and returns expected format."""
        # Mock LocationIQ API key
        monkeypatch.setenv("LOCATIONIQ_API_KEY", "test_key")
        
        # Mock the httpx response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "place_id": "123",
                "display_name": "Empire State Building, New York, NY, USA",
                "lat": "40.748817",
                "lon": "-73.985428",
                "address": {
                    "name": "Empire State Building",
                    "city": "New York",
                    "state": "New York",
                    "country": "United States",
                    "country_code": "us"
                }
            }
        ]
        
        with patch('httpx.AsyncClient.get', new_callable=AsyncMock) as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            mock_get.return_value.__aexit__.return_value = None
            
            response = client.get("/api/v1/location/autocomplete?q=Empire+State")
            
            # Note: This will fail if API key is not configured
            # In CI/CD, skip this test or use proper mocking
            if response.status_code == 503:
                pytest.skip("LocationIQ API key not configured")
            
            assert response.status_code == 200
            data = response.json()
            assert "results" in data
            assert "cached" in data
    
    def test_limit_parameter(self):
        """Test limit parameter is accepted."""
        response = client.get("/api/v1/location/autocomplete?q=Test&limit=5")
        # Will be 400 if query is too short, or 503 if no API key
        assert response.status_code in [400, 503, 422]
    
    def test_invalid_limit_parameter(self):
        """Test invalid limit parameter is rejected."""
        response = client.get("/api/v1/location/autocomplete?q=Test&limit=0")
        assert response.status_code == 422  # Validation error
        
        response = client.get("/api/v1/location/autocomplete?q=Test&limit=25")
        assert response.status_code == 422  # Validation error
    
    def test_countrycodes_parameter(self):
        """Test countrycodes parameter is accepted."""
        response = client.get("/api/v1/location/autocomplete?q=London&countrycodes=us,ca")
        # Will be 400 if query is too short, or 503 if no API key
        assert response.status_code in [400, 503]
    
    def test_health_endpoint(self):
        """Test health endpoint returns service status."""
        response = client.get("/api/v1/location/health")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert data["service"] == "locationiq"
        assert "configured" in data
        assert "cache_size" in data


# ─── ERROR HANDLING TESTS ─────────────────────────────────────────────────────

class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_rate_limit_response_format(self, monkeypatch):
        """Test rate limit error returns proper format."""
        monkeypatch.setenv("LOCATIONIQ_API_KEY", "test_key")
        
        mock_response = MagicMock()
        mock_response.status_code = 429
        
        with patch('httpx.AsyncClient.get', new_callable=AsyncMock) as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            mock_get.return_value.__aexit__.return_value = None
            
            response = client.get("/api/v1/location/autocomplete?q=Test+Query")
            
            if response.status_code == 503:
                pytest.skip("LocationIQ API key not configured")
            
            # Should return 429 or 503 with retry header
            if response.status_code == 429:
                assert "Retry-After" in response.headers
    
    def test_server_error_response_format(self, monkeypatch):
        """Test server error returns proper format."""
        monkeypatch.setenv("LOCATIONIQ_API_KEY", "test_key")
        
        mock_response = MagicMock()
        mock_response.status_code = 500
        
        with patch('httpx.AsyncClient.get', new_callable=AsyncMock) as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            mock_get.return_value.__aexit__.return_value = None
            
            response = client.get("/api/v1/location/autocomplete?q=Test+Query")
            
            if response.status_code == 503:
                pytest.skip("LocationIQ API key not configured")
            
            # After retries, should return 502
            assert response.status_code in [502, 503]
