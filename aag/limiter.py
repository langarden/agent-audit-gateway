# -*- coding: utf-8 -*-
"""Fixed-window rate limiter. Never blocks auth, only rate limits transport."""
import threading
import time


class RateLimiter:
    """Per-key fixed-window limiter. allow(key) -> bool."""

    def __init__(self, limit: int, window_seconds: float = 60.0):
        if limit <= 0:
            raise ValueError("limit must be > 0")
        self._limit = limit
        self._window = window_seconds
        self._lock = threading.Lock()
        self._hits = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = [t for t in self._hits.get(key, []) if now - t < self._window]
            if len(bucket) >= self._limit:
                self._hits[key] = bucket
                return False
            bucket.append(now)
            self._hits[key] = bucket
            return True

    @property
    def limit(self):
        return self._limit

    def reset(self):
        with self._lock:
            self._hits = {}