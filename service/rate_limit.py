"""
Database-backed rate limiter for AIP endpoints.

Uses a `rate_limits` table in SQLite for persistence across restarts.
Provides standard X-RateLimit-* headers on all responses.
"""

import os
import time
from typing import Dict, Tuple

from fastapi import HTTPException

TESTING = os.environ.get("AIP_TESTING") == "1"


def _get_connection():
    """Get a database connection for rate limiting."""
    from database import get_connection
    return get_connection()


class RateLimiter:
    """Database-backed sliding window rate limiter."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def is_allowed(self, key: str) -> Tuple[bool, int]:
        """
        Check if request is allowed for given key.

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: int)
        """
        if TESTING:
            return True, 0

        now = int(time.time())
        window_start = now - (now % self.window_seconds)

        with _get_connection() as conn:
            cursor = conn.cursor()

            # Clean old windows
            cutoff = now - self.window_seconds * 2
            cursor.execute(
                "DELETE FROM rate_limits WHERE window_start < ?",
                (cutoff,)
            )

            # Get current count for this key in the current window
            cursor.execute(
                "SELECT count FROM rate_limits WHERE key = ? AND window_start = ?",
                (key, window_start)
            )
            row = cursor.fetchone()
            current_count = row["count"] if row else 0

            if current_count >= self.max_requests:
                retry_after = self.window_seconds - (now - window_start)
                conn.commit()
                return False, max(1, retry_after)

            # Upsert the count
            cursor.execute(
                """INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
                   ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1""",
                (key, window_start)
            )
            conn.commit()
            return True, 0

    def get_remaining(self, key: str) -> int:
        """Get remaining requests for key in current window."""
        if TESTING:
            return self.max_requests

        now = int(time.time())
        window_start = now - (now % self.window_seconds)

        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT count FROM rate_limits WHERE key = ? AND window_start = ?",
                (key, window_start)
            )
            row = cursor.fetchone()
            current = row["count"] if row else 0
            return max(0, self.max_requests - current)


# Rate limiters for different endpoints
registration_limiter = RateLimiter(max_requests=10, window_seconds=3600)      # 10/hour
easy_registration_limiter = RateLimiter(max_requests=5, window_seconds=3600)  # 5/hour
challenge_limiter = RateLimiter(max_requests=30, window_seconds=60)           # 30/min
vouch_limiter = RateLimiter(max_requests=20, window_seconds=3600)             # 20/hour
message_send_limiter = RateLimiter(max_requests=60, window_seconds=3600)      # 60/hour
message_read_limiter = RateLimiter(max_requests=30, window_seconds=60)        # 30/min
default_limiter = RateLimiter(max_requests=120, window_seconds=60)            # 120/min
verification_limiter = RateLimiter(max_requests=60, window_seconds=60)        # 60/min (kept for compat)


def rate_limit_headers(limiter: RateLimiter, key: str) -> Dict[str, str]:
    """
    Generate standard X-RateLimit-* headers for a successful response.

    Returns dict with:
      - X-RateLimit-Limit: max requests per window
      - X-RateLimit-Remaining: remaining requests in current window
      - X-RateLimit-Reset: Unix timestamp when window resets
    """
    now = int(time.time())
    window_start = now - (now % limiter.window_seconds)
    reset_at = window_start + limiter.window_seconds
    remaining = limiter.get_remaining(key)
    return {
        "X-RateLimit-Limit": str(limiter.max_requests),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset_at),
    }


def check_rate_limit(limiter: RateLimiter, key: str) -> Dict[str, str]:
    """
    Check rate limit and raise HTTPException(429) if exceeded.

    Returns X-RateLimit-* headers dict to attach to the successful response.
    """
    allowed, retry_after = limiter.is_allowed(key)
    if not allowed:
        now = int(time.time())
        window_start = now - (now % limiter.window_seconds)
        reset_at = window_start + limiter.window_seconds
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(limiter.max_requests),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_at),
            },
        )
    # Return headers for successful responses
    return rate_limit_headers(limiter, key)
