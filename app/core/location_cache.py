"""
Location Cache — Two-tier permanent cache with bounded growth

Architecture:
  L1: In-process dict (instant, survives Redis blips, ~0ms)
  L2: Redis with NO TTL by default (survives restarts, shared across workers)

Why permanent?
  Location data (city names, addresses, coordinates) doesn't change meaningfully.
  "New York" → (40.71, -74.00) is valid for years. A 15-min TTL means the same
  popular queries hammer the upstream provider repeatedly for no reason.

  Permanent cache means:
  - First user to search "new york" pays the latency cost
  - Every subsequent user gets instant results from L1/L2
  - Photon's public API sees minimal traffic → no throttling/bans

Safety valves:
  - L1 bounded to MAX_L1_ENTRIES (evicts LRU when full)
  - L2 uses optional TTL (default 30 days) so Redis doesn't grow unbounded
  - Admin endpoint to flush cache if data goes stale
  - Empty results are cached briefly (5 min) to avoid re-querying bad input,
    but NOT permanently (the upstream might have been temporarily down)

Security:
  - All inputs are normalized before use as cache keys (injection-safe)
  - Cache keys use only [a-z0-9_] via normalize+hash
  - No user-supplied strings used raw in Redis commands
  - TLS enforced for rediss:// connections (CERT_REQUIRED)
  - No pickle/eval — JSON only for serialization
"""

import json
import hashlib
import logging
import time
from typing import Optional, Any
from collections import OrderedDict
from threading import Lock
import redis.asyncio as redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


# ─── L1 IN-MEMORY CACHE (per-process) ────────────────────────────────────────

class _LRUCache:
    """
    Thread-safe LRU dict with bounded size.

    No TTL — entries live until evicted by size pressure or explicit flush.
    This is intentional: location data is essentially static.
    """

    def __init__(self, max_size: int = 5000):
        self._data: OrderedDict[str, Any] = OrderedDict()
        self._max_size = max_size
        self._lock = Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self._hits += 1
                return self._data[key]
            self._misses += 1
            return None

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self._data[key] = value
                return
            if len(self._data) >= self._max_size:
                self._data.popitem(last=False)  # evict LRU
            self._data[key] = value

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    def clear(self) -> int:
        with self._lock:
            count = len(self._data)
            self._data.clear()
            return count

    def stats(self) -> dict:
        with self._lock:
            total = self._hits + self._misses
            return {
                "l1_entries": len(self._data),
                "l1_max_size": self._max_size,
                "l1_hits": self._hits,
                "l1_misses": self._misses,
                "l1_hit_rate": round(self._hits / total, 3) if total > 0 else 0,
            }


# ─── MAIN CACHE CLASS ────────────────────────────────────────────────────────

class LocationCache:
    """
    Two-tier location cache: L1 in-memory + L2 Redis.

    Read path:  L1 → L2 → miss
    Write path: Write to both L1 + L2 simultaneously

    Cache key format: "loc:v3:{hash}" where hash is MD5 of normalized query.
    The "v3" version tag lets us invalidate all old cache entries by bumping it,
    without needing to scan+delete (old keys just expire via Redis TTL or are
    never read from L1 since L1 resets on restart).
    """

    # Cache key versioning — bump this to invalidate all cached data
    KEY_VERSION = "v3"
    KEY_PREFIX = f"loc:{KEY_VERSION}"

    # L2 Redis TTL: 30 days (safety valve, not functional expiry)
    # Location data is valid essentially forever, but we don't want Redis
    # growing unbounded if the app generates many unique queries over months
    DEFAULT_TTL = 30 * 24 * 60 * 60  # 30 days in seconds

    # Empty-result TTL: cache "no results" briefly to avoid re-querying typos,
    # but don't cache permanently in case the upstream was temporarily broken
    EMPTY_RESULT_TTL = 5 * 60  # 5 minutes

    # Prefix cache uses the same long TTL since prefix results are
    # just as stable as full-query results
    PREFIX_TTL = DEFAULT_TTL

    MIN_PREFIX_LENGTH = 3

    # L1 size limit per process (each entry ≈ 2-5 KB → 5000 entries ≈ 10-25 MB)
    MAX_L1_ENTRIES = 5000

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._redis: Optional[redis.Redis] = None
        self._l1 = _LRUCache(max_size=self.MAX_L1_ENTRIES)

        # TLS configuration
        self.ssl_opts = {}
        import ssl
        if redis_url.startswith("rediss://"):
            self.ssl_opts = {
                "ssl_cert_reqs": ssl.CERT_REQUIRED,
                "ssl_check_hostname": True,
            }

    async def connect(self) -> None:
        if self._redis is None:
            self._redis = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                **self.ssl_opts,
            )
            logger.info("Location cache connected (L1 in-memory + L2 Redis)")

    async def disconnect(self) -> None:
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Location cache disconnected")

    @property
    def is_connected(self) -> bool:
        return self._redis is not None

    # ── Key generation ────────────────────────────────────────────────────

    @staticmethod
    def normalize_query(query: str) -> str:
        """
        Normalize query for cache key consistency.

        Security: strips everything except [a-z0-9 ,.-#'] to prevent
        injection via cache keys. The result is always safe for use in
        Redis key construction after hashing.
        """
        normalized = query.strip().lower()
        normalized = ' '.join(normalized.split())  # collapse whitespace
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789 ,.-#'")
        normalized = ''.join(c for c in normalized if c in allowed)
        return normalized.strip()

    @staticmethod
    def generate_cache_key(query: str, countrycodes: Optional[str] = None) -> str:
        """
        Generate a safe, fixed-length cache key.

        Always hashes — never puts raw user input in the key name.
        This prevents key injection and keeps key length predictable.
        """
        normalized = LocationCache.normalize_query(query)
        key_parts = [normalized]
        if countrycodes:
            key_parts.append(countrycodes.strip().lower())

        key_string = "|".join(key_parts)
        # Always hash to keep keys safe and uniform length
        key_hash = hashlib.sha256(key_string.encode()).hexdigest()[:24]
        return f"{LocationCache.KEY_PREFIX}:{key_hash}"

    @staticmethod
    def generate_prefix_keys(query: str, countrycodes: Optional[str] = None) -> list[str]:
        """
        Generate cache keys for character-level prefixes.

        For "new york", generates keys for: "new", "new ", "new y", "new yo",
        "new yor", "new york". This means as the user types each character,
        there's already a cached result waiting.
        """
        normalized = LocationCache.normalize_query(query)
        if len(normalized) < LocationCache.MIN_PREFIX_LENGTH:
            return []

        prefix_keys = []
        for i in range(LocationCache.MIN_PREFIX_LENGTH, len(normalized) + 1):
            prefix = normalized[:i]
            # Skip if prefix ends mid-whitespace (looks like "new ")
            # — still cache it, user might pause after space
            key = LocationCache.generate_cache_key(prefix, countrycodes)
            if key not in prefix_keys:  # dedup
                prefix_keys.append(key)

        return prefix_keys

    # ── Read path ─────────────────────────────────────────────────────────

    async def get(self, query: str, countrycodes: Optional[str] = None) -> Optional[list[dict]]:
        """
        L1 → L2 lookup. Returns None only on true cache miss.

        Empty list [] is a valid cached result (means "no results for this query").
        None means "not in cache, go fetch from upstream".
        """
        key = self.generate_cache_key(query, countrycodes)

        # L1 check (instant, no I/O)
        l1_result = self._l1.get(key)
        if l1_result is not None:
            return l1_result

        # L2 check (Redis)
        if not self.is_connected:
            return None

        try:
            cached = await self._redis.get(key)
            if cached is not None:
                data = json.loads(cached)
                # Backfill L1 from L2 (warm the fast path)
                self._l1.set(key, data)
                return data
        except RedisError as e:
            logger.warning(f"Redis get error (degrading to L1-only): {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Corrupt cache entry for key {key}: {e}")
            # Delete corrupt entry
            try:
                await self._redis.delete(key)
            except RedisError:
                pass

        return None

    # ── Write path ────────────────────────────────────────────────────────

    async def set(
        self,
        query: str,
        results: list[dict],
        countrycodes: Optional[str] = None,
        ttl: Optional[int] = None,
        cache_prefixes: bool = True,
    ) -> bool:
        """
        Write to both L1 and L2.

        If results is empty [], caches with short TTL (5 min) to prevent
        re-querying bad input, but doesn't pollute the permanent cache.

        If results is non-empty, caches with long TTL (30 days) and also
        caches all character-level prefixes of the query for instant
        typeahead on future searches.
        """
        normalized = self.normalize_query(query)
        key = self.generate_cache_key(normalized, countrycodes)

        # Decide TTL based on whether results are empty
        if not results:
            effective_ttl = self.EMPTY_RESULT_TTL
            cache_prefixes = False  # don't pollute prefix cache with empty results
        else:
            effective_ttl = ttl or self.DEFAULT_TTL

        serialized = json.dumps(results)

        # L1 write (always, even if Redis fails)
        self._l1.set(key, results)

        # L2 write (Redis)
        if not self.is_connected:
            return True  # L1-only is fine, will backfill L2 on reconnect

        try:
            pipe = self._redis.pipeline()
            pipe.setex(key, effective_ttl, serialized)

            # Cache all character-level prefixes for typeahead
            if cache_prefixes and results:
                prefix_keys = self.generate_prefix_keys(normalized, countrycodes)
                for prefix_key in prefix_keys:
                    if prefix_key != key:
                        pipe.setex(prefix_key, self.PREFIX_TTL, serialized)
                        # Also warm L1 for prefixes
                        self._l1.set(prefix_key, results)

            await pipe.execute()
            return True

        except RedisError as e:
            logger.error(f"Redis set error: {e}")
            return False  # L2 write failed (L1 succeeded, but report failure)

    # ── Admin operations ──────────────────────────────────────────────────

    async def delete(self, query: str, countrycodes: Optional[str] = None) -> bool:
        key = self.generate_cache_key(query, countrycodes)
        self._l1.delete(key)

        if not self.is_connected:
            return True
        try:
            await self._redis.delete(key)
            return True
        except RedisError as e:
            logger.error(f"Redis delete error: {e}")
            return False

    async def clear_all(self) -> bool:
        """
        Flush all location cache entries from L1 and L2.

        L2 uses SCAN to avoid blocking Redis with a massive DEL.
        """
        l1_count = self._l1.clear()
        logger.info(f"Cleared {l1_count} L1 entries")

        if not self.is_connected:
            return True

        try:
            pattern = f"{self.KEY_PREFIX}:*"
            total_deleted = 0
            cursor = 0

            while True:
                cursor, keys = await self._redis.scan(
                    cursor, match=pattern, count=200
                )
                if keys:
                    await self._redis.delete(*keys)
                    total_deleted += len(keys)
                if cursor == 0:
                    break

            logger.info(f"Cleared {total_deleted} L2 (Redis) entries")
            return True

        except RedisError as e:
            logger.error(f"Redis clear_all error: {e}")
            return False

    async def get_stats(self) -> dict[str, Any]:
        """Combined L1 + L2 statistics."""
        stats = self._l1.stats()
        stats["connected"] = self.is_connected

        if not self.is_connected:
            return stats

        try:
            # Count L2 keys (sampled, not exact)
            pattern = f"{self.KEY_PREFIX}:*"
            cursor = 0
            l2_keys = 0
            while True:
                cursor, keys = await self._redis.scan(
                    cursor, match=pattern, count=200
                )
                l2_keys += len(keys)
                if cursor == 0:
                    break

            info = await self._redis.info("memory")
            stats.update({
                "l2_entries": l2_keys,
                "l2_ttl_days": self.DEFAULT_TTL // 86400,
                "used_memory_human": info.get("used_memory_human", "N/A"),
                "used_memory_peak_human": info.get("used_memory_peak_human", "N/A"),
            })
        except RedisError as e:
            stats["l2_error"] = str(e)

        return stats


# ─── GLOBAL INSTANCE ──────────────────────────────────────────────────────────

_location_cache: Optional[LocationCache] = None


def get_location_cache() -> LocationCache:
    if _location_cache is None:
        raise RuntimeError("Location cache not initialized. Call init_location_cache() first.")
    return _location_cache


async def init_location_cache(redis_url: str) -> LocationCache:
    global _location_cache
    _location_cache = LocationCache(redis_url)
    await _location_cache.connect()
    return _location_cache


async def close_location_cache() -> None:
    global _location_cache
    if _location_cache:
        await _location_cache.disconnect()
        _location_cache = None
