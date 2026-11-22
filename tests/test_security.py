import os
import time

import fakeredis
import pytest
import redis

from nexus_sec.security import RateLimiter
from nexus_sec.security import RedisRateLimiter
from nexus_sec.security import build_limiter
from nexus_sec.security import parse_api_keys


# CI also runs these against a real Redis service container
REAL_REDIS_URL = os.getenv("TEST_REDIS_URL")


@pytest.fixture(params=["fakeredis", "redis"])
def redis_client(request):
    if request.param == "fakeredis":
        yield fakeredis.FakeRedis()
        return

    if not REAL_REDIS_URL:
        pytest.skip("TEST_REDIS_URL not set")

    client = redis.Redis.from_url(REAL_REDIS_URL)
    client.flushdb()
    yield client
    client.flushdb()


def test_parse_api_keys_named_and_anonymous():
    keys = parse_api_keys(["alice:key1", "key2"])

    assert keys["key1"] == "alice"
    assert keys["key2"].startswith("key-")


@pytest.mark.parametrize("make_limiter", [
    lambda client: RateLimiter(),
    lambda client: RedisRateLimiter(client),
], ids=["memory", "redis"])
def test_limiter_blocks_after_limit(redis_client, make_limiter):
    limiter = make_limiter(redis_client)

    assert limiter.hit("alice", 2) is None
    assert limiter.hit("alice", 2) is None

    retry_after = limiter.hit("alice", 2)
    assert 1 <= retry_after <= 60

    # Other clients have their own window
    assert limiter.hit("bob", 2) is None


def test_redis_limit_is_shared_across_replicas(redis_client):
    replica_a = RedisRateLimiter(redis_client)
    replica_b = RedisRateLimiter(redis_client)

    assert replica_a.hit("alice", 2) is None
    assert replica_b.hit("alice", 2) is None
    assert replica_a.hit("alice", 2) is not None
    assert replica_b.hit("alice", 2) is not None


def test_redis_window_slides(redis_client):
    limiter = RedisRateLimiter(redis_client, window_seconds=0.2)

    assert limiter.hit("alice", 1) is None
    assert limiter.hit("alice", 1) is not None

    time.sleep(0.25)
    assert limiter.hit("alice", 1) is None


def test_redis_rejected_hits_do_not_extend_the_window(redis_client):
    limiter = RedisRateLimiter(redis_client)

    limiter.hit("alice", 1)
    for _ in range(5):
        limiter.hit("alice", 1)

    [key] = redis_client.keys("nexus:ratelimit:*")
    assert redis_client.zcard(key) == 1


def test_redis_limiter_fails_open(redis_client):
    limiter = RedisRateLimiter(redis_client)

    def unavailable(**kwargs):
        raise ConnectionError("redis down")

    limiter._script = unavailable

    assert limiter.hit("alice", 1) is None
    assert limiter.hit("alice", 1) is None


def test_redis_reset_clears_only_limiter_keys(redis_client):
    redis_client.set("celery-key", "keep")
    limiter = RedisRateLimiter(redis_client)
    limiter.hit("alice", 1)

    limiter.reset()

    assert limiter.hit("alice", 1) is None
    assert redis_client.get("celery-key") == b"keep"


def test_build_limiter_rejects_unknown_backend():
    assert isinstance(build_limiter("memory"), RateLimiter)
    with pytest.raises(ValueError):
        build_limiter("memcached")
