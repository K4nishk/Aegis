"""api/rate_limit.py — Sliding-window rate limiter keyed by ip:user (KCH-19).

Implementation:
  - Redis sorted-set (ZSET) per key, scores = request timestamp in milliseconds.
  - Atomic Lua script: purge old entries, check count, conditionally admit.
  - Key format: rl:{route}:{ip}:{user_id}
  - Fail-open: if Redis is unavailable the request is always allowed (never
    blocks on Redis downtime).

Env vars:
  AEGIS_REDIS_URL       — Redis connection URL (default redis://localhost:6379)
  AEGIS_RL_SCANS_LIMIT  — max requests per window for POST /scans (default 20)
  AEGIS_RL_GATE_LIMIT   — max requests per window for POST /gate (default 60)
  AEGIS_RL_WINDOW       — window size in seconds (default 60)
"""

from __future__ import annotations

import contextlib
import os
import time
import uuid

from fastapi import Depends, HTTPException, Request

from api.deps import get_current_user
from api.security_events import (
    get_request_correlation_id,
    get_request_ip,
    log_rate_limit_hit,
)

# ---------------------------------------------------------------------------
# Lua script — atomic sliding-window check-and-admit
# ---------------------------------------------------------------------------

_SLIDING_WINDOW_LUA = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local ttl    = tonumber(ARGV[4])

-- Purge entries outside the sliding window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
-- Count in-window entries
local count = redis.call('ZCARD', key)
if count < limit then
    -- Append a per-key sequence number so simultaneous requests get unique members
    local seq = redis.call('INCR', key .. ':seq')
    redis.call('ZADD', key, now, tostring(now) .. ':' .. tostring(seq))
    redis.call('EXPIRE', key, ttl)
    return 1
end
return 0
"""


def _get_redis():  # type: ignore[return]
    """Return a connected Redis client or None if unavailable (best-effort)."""
    redis_url = os.environ.get("AEGIS_REDIS_URL", "redis://localhost:6379")
    try:
        import redis  # type: ignore[import-untyped]

        r = redis.Redis.from_url(redis_url, socket_connect_timeout=1, decode_responses=True)
        r.ping()
        return r
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Limiter
# ---------------------------------------------------------------------------


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter backed by Redis sorted sets.

    Parameters
    ----------
    limit:
        Maximum admitted requests within *window_seconds*.
    window_seconds:
        Width of the sliding window.
    route:
        Short label embedded in the Redis key (e.g. ``"scans"``).
    """

    def __init__(self, *, limit: int, window_seconds: int, route: str) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.route = route

    def is_allowed(self, ip: str, user_id: str) -> bool:
        """Return True if admitted, False to reject with 429.

        Always returns True when Redis is unreachable (fail-open).
        """
        r = _get_redis()
        if r is None:
            return True

        now_ms = int(time.time() * 1000)
        window_ms = self.window_seconds * 1000
        key = f"rl:{self.route}:{ip}:{user_id}"
        ttl = self.window_seconds + 1

        try:
            result = r.eval(_SLIDING_WINDOW_LUA, 1, key, now_ms, window_ms, self.limit, ttl)
            return bool(result)
        except Exception:  # noqa: BLE001
            return True  # fail open on any Redis error
        finally:
            with contextlib.suppress(Exception):
                r.close()


# ---------------------------------------------------------------------------
# Pre-built limiter singletons — constructed lazily so env vars set after
# import time (common in tests) take effect.
# ---------------------------------------------------------------------------


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default


_scans_limiter: SlidingWindowRateLimiter | None = None
_gate_limiter: SlidingWindowRateLimiter | None = None


def get_scans_limiter() -> SlidingWindowRateLimiter:
    global _scans_limiter
    if _scans_limiter is None:
        _scans_limiter = SlidingWindowRateLimiter(
            limit=_env_int("AEGIS_RL_SCANS_LIMIT", 20),
            window_seconds=_env_int("AEGIS_RL_WINDOW", 60),
            route="scans",
        )
    return _scans_limiter


def get_gate_limiter() -> SlidingWindowRateLimiter:
    global _gate_limiter
    if _gate_limiter is None:
        _gate_limiter = SlidingWindowRateLimiter(
            limit=_env_int("AEGIS_RL_GATE_LIMIT", 60),
            window_seconds=_env_int("AEGIS_RL_WINDOW", 60),
            route="gate",
        )
    return _gate_limiter


def reset_limiters() -> None:
    """Reset singleton limiters — for tests that override env vars."""
    global _scans_limiter, _gate_limiter
    _scans_limiter = None
    _gate_limiter = None


# ---------------------------------------------------------------------------
# FastAPI dependencies — one per rate-limited route
# ---------------------------------------------------------------------------


async def scans_rate_limit(
    request: Request,  # noqa: ARG001
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> None:
    """Dependency: sliding-window rate limit for POST /scans."""
    ip = get_request_ip()
    if not get_scans_limiter().is_allowed(ip, str(user_id)):
        log_rate_limit_hit(
            ip=ip,
            actor=str(user_id),
            correlation_id=get_request_correlation_id(),
        )
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please slow down.",
            headers={"Retry-After": str(get_scans_limiter().window_seconds)},
        )


async def gate_rate_limit(
    request: Request,  # noqa: ARG001
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> None:
    """Dependency: sliding-window rate limit for POST /gate."""
    ip = get_request_ip()
    if not get_gate_limiter().is_allowed(ip, str(user_id)):
        log_rate_limit_hit(
            ip=ip,
            actor=str(user_id),
            correlation_id=get_request_correlation_id(),
        )
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please slow down.",
            headers={"Retry-After": str(get_gate_limiter().window_seconds)},
        )
