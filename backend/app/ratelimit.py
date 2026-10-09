"""Per-IP rate limits for the public API (NFR-5, docs/06-api-spec.md).

In-process sliding window: enough for one server. Behind a proxy, run uvicorn with
--proxy-headers so the client address is the real one.
"""

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self, limit: int, window_s: float = 60.0) -> None:
        self.limit = limit
        self.window_s = window_s
        self._hits: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window_s:
                hits.popleft()
            if len(hits) >= self.limit:
                retry = int(self.window_s - (now - hits[0])) + 1
                raise HTTPException(
                    429, "Too many requests. Try again shortly.", {"Retry-After": str(retry)}
                )
            hits.append(now)
            if len(self._hits) > 10_000:  # drop idle clients
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    async def __call__(self, request: Request) -> None:
        self.check(request.client.host if request.client else "unknown")


analyze_limit = RateLimiter(20)
feedback_limit = RateLimiter(60)
