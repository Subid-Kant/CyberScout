"""
rate_limiter.py
In-memory per-IP rate limiter using a sliding window.
No Redis required — suitable for single-process deployments.
"""

import time
import threading
from collections import defaultdict, deque
from functools import wraps
from flask import request, jsonify


class RateLimiter:
    def __init__(self, max_calls: int = 5, period: int = 60):
        """
        :param max_calls: Maximum allowed calls per period per IP.
        :param period:    Window in seconds.
        """
        self.max_calls = max_calls
        self.period    = period
        self._calls    = defaultdict(deque)
        self._lock     = threading.Lock()

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """
        Returns (allowed, retry_after_seconds).
        """
        now = time.monotonic()
        window_start = now - self.period

        with self._lock:
            q = self._calls[key]
            # Evict timestamps older than window
            while q and q[0] < window_start:
                q.popleft()

            if len(q) >= self.max_calls:
                retry_after = int(self.period - (now - q[0])) + 1
                return False, retry_after

            q.append(now)
            return True, 0

    def limit(self, max_calls: int = None, period: int = None):
        """Decorator factory for Flask route rate limiting."""
        _max   = max_calls or self.max_calls
        _period = period or self.period

        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                ip = request.remote_addr or "unknown"
                allowed, retry_after = self.is_allowed(f"{ip}:{f.__name__}")
                if not allowed:
                    return jsonify({
                        "error":       "Rate limit exceeded",
                        "retry_after": retry_after,
                        "message":     f"Maximum {_max} requests per {_period}s per IP."
                    }), 429
                return f(*args, **kwargs)
            return wrapper
        return decorator


# Global instance — 5 scans per minute per IP
scan_limiter = RateLimiter(max_calls=5, period=60)
