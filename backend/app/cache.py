"""Cache for external lookups (CLAUDE.md: lookups must be cached).

Uses Redis when REDIS_URL is set, otherwise an in-process TTL cache so the demo
laptop needs no extra service. Values must be JSON-serialisable.
"""

import json
import logging
import os
import time
from typing import Any, Protocol

log = logging.getLogger(__name__)

DEFAULT_TTL_S = 24 * 3600


class Cache(Protocol):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL_S) -> None: ...


class MemoryCache:
    def __init__(self, max_items: int = 10_000):
        self._data: dict[str, tuple[float, str]] = {}
        self._max = max_items

    async def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, raw = item
        if expires < time.monotonic():
            del self._data[key]
            return None
        return json.loads(raw)

    async def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL_S) -> None:
        if len(self._data) >= self._max:
            # Drop the entry closest to expiry.
            del self._data[min(self._data, key=lambda k: self._data[k][0])]
        self._data[key] = (time.monotonic() + ttl, json.dumps(value))


class RedisCache:
    def __init__(self, url: str):
        import redis.asyncio as redis

        self._r = redis.from_url(url)

    async def get(self, key: str) -> Any | None:
        try:
            raw = await self._r.get(f"lid:{key}")
        except Exception:
            # Cache trouble must not fail a request.
            log.warning("redis get failed for %s", key, exc_info=True)
            return None
        return None if raw is None else json.loads(raw)

    async def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL_S) -> None:
        try:
            await self._r.set(f"lid:{key}", json.dumps(value), ex=ttl)
        except Exception:
            log.warning("redis set failed for %s", key, exc_info=True)


_cache: Cache | None = None


def get_cache() -> Cache:
    global _cache
    if _cache is None:
        url = os.environ.get("REDIS_URL")
        _cache = RedisCache(url) if url else MemoryCache()
    return _cache
