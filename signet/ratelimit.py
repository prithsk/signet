"""Fixed-window rate limiter, in memory. Good for one process; swap for Redis if you scale out."""
from __future__ import annotations

import threading
import time

from fastapi import HTTPException


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, tuple[int, int]] = {}  # key -> (window_start, count)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: int) -> None:
        now = int(time.time())
        start = now - now % window
        with self._lock:
            w, n = self._hits.get(key, (start, 0))
            if w != start:
                w, n = start, 0
            n += 1
            self._hits[key] = (w, n)
            if len(self._hits) > 50_000:  # crude bound on memory
                self._hits = {k: v for k, v in self._hits.items() if v[0] == start}
        if n > limit:
            raise HTTPException(429, "rate limited, try again later")
