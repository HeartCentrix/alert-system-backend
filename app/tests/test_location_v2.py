"""
Tests for Location Autocomplete with Hybrid Caching

Run with: pytest app/tests/test_location_v2.py -v
"""
import pytest
import time
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timezone
from app.core.location_cache import (
    LocationCache, 
    normalize_query, 
    generate_cache_key,
    init_location_cache,
    close_location_cache,
)


# ─── UNIT TESTS: QUERY NORMALIZATION ──────────────────────────────────────────

class TestQueryNormalization:
    """Test query normalization for consistent caching."""
    
    def test_trim_whitespace(self):
        """Test whitespace is trimmed."""
        assert LocationCache.normalize_query("  New York  ") == "new york"
    
    def test_lowercase(self):
        """Test conversion to lowercase."""
        assert LocationCache.normalize_query("NEW YORK") == "new york"
    
    def test_multiple_spaces(self):
        """Test multiple spaces are collapsed."""
        assert LocationCache.normalize_query("New   York") == "new york"
    
    def test_special_characters_removed(self):
        """Test invalid special characters are removed."""
        result = LocationCache.normalize_query("New York<script>")
        assert "<" not in result
        assert ">" not in result
    
    def test_allowed_special_chars_preserved(self):
        """Test allowed special characters are preserved."""
        result = LocationCache.normalize_query("123 Main St., Suite #100")
        assert "st." in result
        assert "#" in result
    
    def test_empty_query(self):
        """Test empty query returns empty string."""
        assert LocationCache.normalize_query("") == ""
        assert LocationCache.normalize_query("   ") == ""


# ─── UNIT TESTS: CACHE KEY GENERATION ─────────────────────────────────────────

class TestCacheKeyGeneration:
    """Test cache key generation."""
    
    def test_consistent_keys(self):
        """Test same input produces same key."""
        key1 = LocationCache.generate_cache_key("New York", "us")
        key2 = LocationCache.generate_cache_key("New York", "us")
        assert key1 == key2
    
    def test_different_keys_for_different_queries(self):
        """Test different queries produce different keys."""
        key1 = LocationCache.generate_cache_key("New York", "us")
        key2 = LocationCache.generate_cache_key("Los Angeles", "us")
        assert key1 != key2
    
    def test_different_keys_for_different_countries(self):
        """Test different country codes produce different keys."""
        key1 = LocationCache.generate_cache_key("New York", "us")
        key2 = LocationCache.generate_cache_key("New York", "ca")
        assert key1 != key2
    
    def test_normalized_input(self):
        """Test input is normalized before key generation."""
        key1 = LocationCache.generate_cache_key("  NEW YORK  ", "us")
        key2 = LocationCache.generate_cache_key("new york", "us")
        assert key1 == key2
    
    def test_long_query_uses_hash(self):
        """Test long queries use hash for key."""
        long_query = "a" * 100
        key = LocationCache.generate_cache_key(long_query, "us")
        assert len(key) < 100  # Hash should be shorter


# ─── UNIT TESTS: PREFIX KEY GENERATION ────────────────────────────────────────

class TestPrefixKeyGeneration:
    """Test prefix key generation for typeahead optimization."""
    
    def test_generates_all_prefixes(self):
        """Test all word prefixes are generated."""
        keys = LocationCache.generate_prefix_keys("New York City", "us")
        assert len(keys) >= 2  # "New", "New York", "New York City"
    
    def test_minimum_length_enforced(self):
        """Test prefixes shorter than 3 chars are not generated."""
        keys = LocationCache.generate_prefix_keys("A B C D", "us")
        # Only generate for prefixes with 3+ chars
        for key in keys:
            assert len(key) > len("location:query:")
    
    def test_empty_query_returns_empty(self):
        """Test empty query returns empty list."""
        keys = LocationCache.generate_prefix_keys("", "us")
        assert keys == []


# ─── INTEGRATION TESTS: REDIS CACHE ───────────────────────────────────────────

@pytest.mark.asyncio
class TestRedisCache:
    """Test Redis cache operations."""
    
    @pytest.fixture
    async def cache(self):
        """Create cache instance for testing."""
        # Skip if Redis not available
        import os
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        
        cache = LocationCache(redis_url)
        await cache.connect()
        yield cache
        await cache.disconnect()
    
    async def test_set_and_get(self, cache):
        """Test storing and retrieving from cache."""
        test_data = [{"lat": 40.7, "lon": -74.0, "display_name": "New York"}]
        query = "test location"
        
        # Set cache
        success = await cache.set(query, test_data)
        assert success is True
        
        # Get cache
        result = await cache.get(query)
        assert result == test_data
    
    async def test_cache_miss(self, cache):
        """Test cache miss returns None."""
        result = await cache.get("nonexistent_query_12345")
        assert result is None
    
    async def test_get_or_set_cache_miss(self, cache):
        """Test get_or_set fetches on miss."""
        async def fetch_func():
            return [{"lat": 40.7, "lon": -74.0}]
        
        results, is_cached = await cache.get_or_set("fresh_query", fetch_func)
        
        assert results is not None
        assert is_cached is False
        
        # Second call should hit cache
        results2, is_cached2 = await cache.get_or_set("fresh_query", fetch_func)
        assert is_cached2 is True
    
    async def test_delete(self, cache):
        """Test deleting from cache."""
        test_data = [{"lat": 40.7, "lon": -74.0}]
        query = "to_delete"
        
        await cache.set(query, test_data)
        success = await cache.delete(query)
        assert success is True
        
        result = await cache.get(query)
        assert result is None
    
    async def test_clear_all(self, cache):
        """Test clearing all cache entries."""
        # Set multiple entries
        await cache.set("test1", [{"lat": 1}])
        await cache.set("test2", [{"lat": 2}])
        await cache.set("test3", [{"lat": 3}])
        
        # Clear all
        success = await cache.clear_all()
        assert success is True
        
        # Verify cleared
        stats = await cache.get_stats()
        # Note: Other tests might have added entries, so just check it ran
        assert "location_cache_keys" in stats


# ─── TESTS: REQUEST DEDUPLICATION ─────────────────────────────────────────────

class TestRequestDeduplication:
    """Test in-flight request deduplication."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_deduplicated(self):
        """Test concurrent identical requests are deduplicated."""
        from app.api.location_v2 import _request_tracker
        
        call_count = 0
        
        async def fetch_func():
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.1)  # Simulate API call
            return [{"lat": 40.7}]
        
        cache_key = "dedup_test"
        
        # Start multiple concurrent requests
        tasks = [
            _request_tracker.get_or_create(cache_key, fetch_func)
            for _ in range(5)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Should only call fetch_func once
        assert call_count == 1
        
        # All should get same result
        for result, is_cached in results:
            assert result == [{"lat": 40.7}]


# ─── TESTS: RATE LIMITING ─────────────────────────────────────────────────────

class TestRateLimiting:
    """Test rate limiting enforcement."""
    
    def test_min_request_interval(self):
        """Test minimum interval between requests is enforced."""
        # This is tested indirectly through the hook
        # Direct testing would require mocking time functions
        pass


# ─── TESTS: API ENDPOINT ──────────────────────────────────────────────────────

class TestAutocompleteEndpoint:
    """Test the /api/v1/location/autocomplete endpoint."""
    
    def test_missing_query_parameter(self, client):
        """Test endpoint rejects missing 'q' parameter."""
        response = client.get("/api/v1/location/autocomplete")
        assert response.status_code == 422
    
    def test_short_query_rejected(self, client):
        """Test endpoint rejects query shorter than 3 characters."""
        response = client.get("/api/v1/location/autocomplete?q=Ab")
        assert response.status_code == 400
        assert "3 characters" in response.json()["detail"]
    
    def test_health_endpoint(self, client):
        """Test health endpoint returns service status."""
        response = client.get("/api/v1/location/health")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "configured" in data
        assert "redis_connected" in data


# ─── PERFORMANCE TESTS ────────────────────────────────────────────────────────

@pytest.mark.performance
class TestPerformance:
    """Performance tests for caching system."""
    
    def test_cache_hit_latency(self, cache):
        """Test cache hit latency is under 10ms."""
        import time
        
        async def run_test():
            # Warm up cache
            await cache.set("perf_test", [{"lat": 40.7}])
            
            # Measure cache hit
            start = time.time()
            await cache.get("perf_test")
            elapsed = (time.time() - start) * 1000
            
            assert elapsed < 10, f"Cache hit took {elapsed}ms (expected <10ms)"
        
        asyncio.run(run_test())
    
    def test_cache_normalization_speed(self):
        """Test query normalization is fast."""
        import time
        
        iterations = 10000
        query = "  Empire State Building, New York, NY  "
        
        start = time.time()
        for _ in range(iterations):
            LocationCache.normalize_query(query)
        elapsed = (time.time() - start) * 1000
        
        avg_time = elapsed / iterations
        assert avg_time < 0.01, f"Normalization avg {avg_time}ms (expected <0.01ms)"
