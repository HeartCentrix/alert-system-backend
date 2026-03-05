"""
Redis Cache Utility for Location Autocomplete

Provides efficient caching layer with query normalization, prefix caching,
and automatic TTL management.
"""
import json
import hashlib
import logging
from typing import Optional, Any
import redis.asyncio as redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class LocationCache:
    """
    Redis-based cache for location autocomplete queries.
    
    Features:
    - Query normalization (trim, lowercase, remove extra spaces)
    - Prefix caching (cache partial queries for faster typeahead)
    - Automatic TTL management
    - JSON serialization/deserialization
    - Error handling with graceful degradation
    """
    
    # Cache key prefix
    KEY_PREFIX = "location:query"
    
    # TTL in seconds
    DEFAULT_TTL = 900  # 15 minutes
    PREFIX_TTL = 300   # 5 minutes for prefix cache
    
    # Minimum query length for prefix caching
    MIN_PREFIX_LENGTH = 3
    
    def __init__(self, redis_url: str):
        """
        Initialize Redis cache connection.
        
        Args:
            redis_url: Redis connection URL (e.g., redis://localhost:6379/0)
        """
        self.redis_url = redis_url
        self._redis: Optional[redis.Redis] = None
    
    async def connect(self) -> None:
        """Establish Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            logger.info("Redis cache connected")
    
    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Redis cache disconnected")
    
    @property
    def is_connected(self) -> bool:
        """Check if Redis is connected."""
        return self._redis is not None
    
    @staticmethod
    def normalize_query(query: str) -> str:
        """
        Normalize query for consistent caching.
        
        Args:
            query: Raw search query
            
        Returns:
            Normalized query (trimmed, lowercase, single spaces)
        """
        # Trim whitespace
        normalized = query.strip()
        # Convert to lowercase
        normalized = normalized.lower()
        # Replace multiple spaces with single space
        normalized = ' '.join(normalized.split())
        # Remove special characters except common address chars
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789 ,.-#'")
        normalized = ''.join(c for c in normalized if c in allowed)
        # Final trim
        return normalized.strip()
    
    @staticmethod
    def generate_cache_key(query: str, countrycodes: Optional[str] = None) -> str:
        """
        Generate consistent cache key for query.
        
        Args:
            query: Normalized search query
            countrycodes: Optional country filter
            
        Returns:
            Cache key string
        """
        normalized = LocationCache.normalize_query(query)
        
        # Create key components
        key_parts = [normalized]
        if countrycodes:
            key_parts.append(countrycodes.lower())
        
        # For short queries, use hash to keep key length reasonable
        key_string = "|".join(key_parts)
        
        if len(key_string) > 50:
            # Use MD5 hash for long keys
            key_hash = hashlib.md5(key_string.encode()).hexdigest()[:16]
            return f"{LocationCache.KEY_PREFIX}:{key_hash}"
        
        # For short keys, use readable format
        safe_key = key_string.replace(" ", "_").replace("|", "_")
        return f"{LocationCache.KEY_PREFIX}:{safe_key}"
    
    @staticmethod
    def generate_prefix_keys(query: str, countrycodes: Optional[str] = None) -> list[str]:
        """
        Generate cache keys for all prefixes of the query.
        
        Args:
            query: Search query
            countrycodes: Optional country filter
            
        Returns:
            List of cache keys for prefixes (min 3 chars)
        """
        normalized = LocationCache.normalize_query(query)
        words = normalized.split()
        
        prefix_keys = []
        current_prefix = ""
        
        for i, word in enumerate(words):
            if i > 0:
                current_prefix += " "
            current_prefix += word
            
            # Only cache prefixes with 3+ characters
            if len(current_prefix) >= LocationCache.MIN_PREFIX_LENGTH:
                key = LocationCache.generate_cache_key(current_prefix, countrycodes)
                prefix_keys.append(key)
        
        return prefix_keys
    
    async def get(self, query: str, countrycodes: Optional[str] = None) -> Optional[list[dict]]:
        """
        Retrieve cached location results.
        
        Args:
            query: Search query
            countrycodes: Optional country filter
            
        Returns:
            Cached results or None if not found
        """
        if not self.is_connected:
            return None
        
        try:
            key = self.generate_cache_key(query, countrycodes)
            cached = await self._redis.get(key)
            
            if cached:
                data = json.loads(cached)
                logger.debug(f"Cache hit for query: {query}")
                return data
            
            logger.debug(f"Cache miss for query: {query}")
            return None
            
        except RedisError as e:
            logger.error(f"Redis get error: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Cache JSON decode error: {e}")
            return None
    
    async def set(
        self,
        query: str,
        results: list[dict],
        countrycodes: Optional[str] = None,
        ttl: Optional[int] = None,
        cache_prefixes: bool = True,
    ) -> bool:
        """
        Cache location results with optional prefix caching.
        
        Args:
            query: Search query
            results: Location results to cache
            countrycodes: Optional country filter
            ttl: Optional custom TTL (defaults to 900s)
            cache_prefixes: Whether to cache query prefixes
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_connected:
            return False
        
        try:
            normalized = self.normalize_query(query)
            ttl = ttl or self.DEFAULT_TTL
            
            # Cache the full query
            key = self.generate_cache_key(normalized, countrycodes)
            serialized = json.dumps(results)
            
            # Use pipeline for atomic operations
            pipe = self._redis.pipeline()
            pipe.setex(key, ttl, serialized)
            
            # Cache prefixes for faster typeahead
            if cache_prefixes:
                prefix_keys = self.generate_prefix_keys(normalized, countrycodes)
                for prefix_key in prefix_keys:
                    if prefix_key != key:  # Don't duplicate the full query
                        pipe.setex(prefix_key, self.PREFIX_TTL, serialized)
            
            await pipe.execute()
            logger.debug(f"Cached {len(results)} results for query: {query}")
            return True
            
        except RedisError as e:
            logger.error(f"Redis set error: {e}")
            return False
        except (json.JSONEncodeError, TypeError) as e:
            logger.error(f"Cache JSON encode error: {e}")
            return False
    
    async def get_or_set(
        self,
        query: str,
        fetch_func,
        countrycodes: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> tuple[list[dict], bool]:
        """
        Get from cache or fetch and cache.
        
        Args:
            query: Search query
            fetch_func: Async function to call if cache miss
            countrycodes: Optional country filter
            ttl: Optional custom TTL
            
        Returns:
            Tuple of (results, is_cached)
        """
        # Try cache first
        cached = await self.get(query, countrycodes)
        if cached is not None:
            return cached, True
        
        # Cache miss - fetch fresh data
        results = await fetch_func()
        
        # Cache the results
        if results:
            await self.set(query, results, countrycodes, ttl)
        
        return results, False
    
    async def delete(self, query: str, countrycodes: Optional[str] = None) -> bool:
        """
        Delete cached results for a query.
        
        Args:
            query: Search query
            countrycodes: Optional country filter
            
        Returns:
            True if deleted, False otherwise
        """
        if not self.is_connected:
            return False
        
        try:
            key = self.generate_cache_key(query, countrycodes)
            await self._redis.delete(key)
            logger.debug(f"Deleted cache for query: {query}")
            return True
        except RedisError as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    async def clear_all(self) -> bool:
        """
        Clear all location cache entries.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.is_connected:
            return False
        
        try:
            # Find all location cache keys
            pattern = f"{self.KEY_PREFIX}:*"
            cursor = 0
            
            while True:
                cursor, keys = await self._redis.scan(cursor, match=pattern, count=100)
                if keys:
                    await self._redis.delete(*keys)
                    logger.info(f"Cleared {len(keys)} cache entries")
                
                if cursor == 0:
                    break
            
            return True
            
        except RedisError as e:
            logger.error(f"Redis clear_all error: {e}")
            return False
    
    async def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        if not self.is_connected:
            return {"connected": False}
        
        try:
            # Count location cache keys
            pattern = f"{self.KEY_PREFIX}:*"
            cursor = 0
            total_keys = 0
            
            while True:
                cursor, keys = await self._redis.scan(cursor, match=pattern, count=100)
                total_keys += len(keys)
                if cursor == 0:
                    break
            
            # Get Redis info
            info = await self._redis.info("memory")
            
            return {
                "connected": True,
                "location_cache_keys": total_keys,
                "used_memory_human": info.get("used_memory_human", "N/A"),
                "used_memory_peak_human": info.get("used_memory_peak_human", "N/A"),
            }
            
        except RedisError as e:
            logger.error(f"Redis stats error: {e}")
            return {"connected": False, "error": str(e)}


# Global cache instance (initialized in app startup)
_location_cache: Optional[LocationCache] = None


def get_location_cache() -> LocationCache:
    """Get the global location cache instance."""
    if _location_cache is None:
        raise RuntimeError("Location cache not initialized. Call init_location_cache() first.")
    return _location_cache


async def init_location_cache(redis_url: str) -> LocationCache:
    """
    Initialize the global location cache.
    
    Args:
        redis_url: Redis connection URL
        
    Returns:
        Initialized LocationCache instance
    """
    global _location_cache
    _location_cache = LocationCache(redis_url)
    await _location_cache.connect()
    return _location_cache


async def close_location_cache() -> None:
    """Close the global location cache connection."""
    global _location_cache
    if _location_cache:
        await _location_cache.disconnect()
        _location_cache = None
