# security.py
#
# API-key authentication and upload rate limiting.

import hashlib
import hmac
import logging
import math
import threading
import time
import uuid
from collections import defaultdict
from collections import deque
from dataclasses import dataclass

from fastapi import Header
from fastapi import HTTPException
from fastapi import Request

from nexus_sec import config

logger = logging.getLogger(__name__)

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
    """In-memory sliding window, per API process."""

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


# Sliding window as a sorted set of hit timestamps. Runs atomically in Redis,
# using the server's clock so API replicas with skewed clocks still agree.
# Returns -1 when the hit is allowed, else milliseconds until it would be.
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
if redis.call('ZCARD', key) >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    return tonumber(oldest[2]) + window - now
end

redis.call('ZADD', key, now, ARGV[3])
redis.call('PEXPIRE', key, window)
return -1
"""


class RedisRateLimiter:
    """Sliding window shared by every API replica."""

    def __init__(self, client, window_seconds=60.0, prefix="nexus:ratelimit:"):
        self.window_ms = int(window_seconds * 1000)
        self.prefix = prefix
        self._client = client
        self._script = client.register_script(_SLIDING_WINDOW_LUA)

    def hit(self, key, limit):
        """Record a hit; return seconds to wait if over the limit, else None."""

        try:
            wait_ms = self._script(
                keys=[self.prefix + key],
                args=[limit, self.window_ms, uuid.uuid4().hex]
            )
        except Exception:
            # Fail open: an unreachable Redis must not turn into rejected
            # uploads (the enqueue step reports the outage instead)
            logger.warning("Rate limiter unavailable; allowing request", exc_info=True)
            return None

        if wait_ms < 0:
            return None
        return max(1, math.ceil(wait_ms / 1000))

    def reset(self):
        for key in self._client.scan_iter(match=self.prefix + "*"):
            self._client.delete(key)


def build_limiter(backend=None):
    backend = backend or config.RATE_LIMIT_BACKEND
    if backend == "memory":
        return RateLimiter()
    if backend == "redis":
        import redis

        client = redis.Redis.from_url(config.REDIS_URL, socket_timeout=1)
        return RedisRateLimiter(client)
    raise ValueError(f"Unknown RATE_LIMIT_BACKEND: {backend!r}")


upload_limiter = build_limiter()


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
