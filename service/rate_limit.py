"""
Simple in-memory rate limiter for AIP endpoints.

Provides sliding window rate limiting per IP address.
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple
import threading


class RateLimiter:
    """Thread-safe sliding window rate limiter."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """
        Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed per window
            window_seconds: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, key: str) -> Tuple[bool, int]:
        """
        Check if request is allowed for given key.

        Args:
            key: Identifier (usually IP address)

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self.lock:
            # Clean old requests
            self.requests[key] = [t for t in self.requests[key] if t > cutoff]

            # Check limit
            if len(self.requests[key]) >= self.max_requests:
                # Calculate when oldest request expires
                oldest = min(self.requests[key])
                retry_after = int(oldest + self.window_seconds - now) + 1
                return False, max(1, retry_after)

            # Allow and record
            self.requests[key].append(now)
            return True, 0

    def get_remaining(self, key: str) -> int:
        """Get remaining requests for key in current window."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self.lock:
            current = len([t for t in self.requests[key] if t > cutoff])
            return max(0, self.max_requests - current)

    def cleanup(self):
        """Remove stale entries to prevent memory growth."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self.lock:
            # Remove keys with no recent requests
            stale_keys = [
                k for k, v in self.requests.items()
                if not any(t > cutoff for t in v)
            ]
            for k in stale_keys:
                del self.requests[k]


# Default rate limiters for different endpoints
registration_limiter = RateLimiter(max_requests=5, window_seconds=60)  # 5 per minute
verification_limiter = RateLimiter(max_requests=60, window_seconds=60)  # 60 per minute
vouch_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 per minute
