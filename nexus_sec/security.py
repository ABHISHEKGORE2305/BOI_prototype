# security.py
#
# API-key authentication and upload rate limiting.

import hashlib
import hmac
import threading
import time
from collections import defaultdict
from collections import deque
from dataclasses import dataclass

from fastapi import Header
from fastapi import HTTPException
from fastapi import Request

from nexus_sec import config

ANONYMOUS = "anonymous"


@dataclass(frozen=True)
class Principal:
    name: str
    authenticated: bool


def parse_api_keys(entries):
    """["alice:key1", "key2"] -> {"key1": "alice", "key2": "key-<hash>"}"""

    keys = {}
    for entry in entries:
        name, sep, key = entry.partition(":")
        if not sep:
            key = entry
            name = "key-" + hashlib.sha256(key.encode()).hexdigest()[:8]
        keys[key] = name
    return keys


def authenticate(x_api_key: str | None = Header(default=None)):
    keys = parse_api_keys(config.API_KEYS)

    if not keys:
        return Principal(ANONYMOUS, authenticated=False)

    if x_api_key:
        for key, name in keys.items():
            if hmac.compare_digest(key.encode(), x_api_key.encode()):
                return Principal(name, authenticated=True)

    raise HTTPException(
        status_code=401,
        detail="Invalid or missing API key",
        headers={"WWW-Authenticate": "ApiKey"}
    )


class RateLimiter:
    """In-memory sliding window. Per API process; use Redis for several replicas."""

    def __init__(self, window_seconds=60.0):
        self.window = window_seconds
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key, limit):
        """Record a hit; return seconds to wait if over the limit, else None."""

        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= limit:
                return max(1, int(hits[0] + self.window - now) + 1)
            hits.append(now)
            return None

    def reset(self):
        with self._lock:
            self._hits.clear()


upload_limiter = RateLimiter()


def enforce_upload_rate_limit(request: Request, principal: Principal):
    limit = config.UPLOAD_RATE_LIMIT_PER_MINUTE
    if limit <= 0:
        return

    key = principal.name if principal.authenticated else (
        request.client.host if request.client else "unknown"
    )

    retry_after = upload_limiter.hit(key, limit)
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Upload rate limit exceeded",
            headers={"Retry-After": str(retry_after)}
        )
