"""api/security_events.py — Structured security-event logging + spike detection (KCH-21).

Exports:
  log_auth_failure(...)        — failed login / bad API key
  log_permission_denied(...)   — 403 / ownership violation
  log_rate_limit_hit(...)      — 429 (future rate-limiter hook)

All functions emit a structlog record under the ``aegis.security`` logger with a
``security_event`` field that CloudWatch metric filters can match on.

Spike detection (Redis):
  Each auth failure increments a per-IP counter in Redis with a 15-minute TTL.
  When the count reaches AEGIS_SPIKE_THRESHOLD (default 20) the function also
  emits a ``security_event=spike_alert`` CRITICAL record, which a separate
  CloudWatch alarm (see infra/cloudwatch_alarm.tf) converts into a PagerDuty page.

  Redis connection is best-effort: if AEGIS_REDIS_URL is unset or Redis is
  unreachable, spike detection is silently skipped so the main auth path is
  never blocked.
"""

from __future__ import annotations

import contextvars
import os

import structlog

# Importing logging_config auto-configures structlog to route through stdlib.
import api.logging_config  # noqa: F401

_SEC_LOG: structlog.stdlib.BoundLogger = structlog.get_logger("aegis.security")

# ---------------------------------------------------------------------------
# Per-request context (set by CorrelationIdMiddleware, read by auth deps)
# ---------------------------------------------------------------------------

_request_ip: contextvars.ContextVar[str] = contextvars.ContextVar("request_ip", default="unknown")
_request_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_correlation_id", default=None
)


def set_request_context(ip: str, correlation_id: str | None) -> None:
    """Called once per request by CorrelationIdMiddleware."""
    _request_ip.set(ip)
    _request_correlation_id.set(correlation_id)


def get_request_ip() -> str:
    return _request_ip.get()


def get_request_correlation_id() -> str | None:
    return _request_correlation_id.get()

# ---------------------------------------------------------------------------
# Spike detection config
# ---------------------------------------------------------------------------

_SPIKE_THRESHOLD = int(os.environ.get("AEGIS_SPIKE_THRESHOLD", "20"))
_SPIKE_WINDOW_SECONDS = int(os.environ.get("AEGIS_SPIKE_WINDOW", "900"))  # 15 min
_REDIS_URL = os.environ.get("AEGIS_REDIS_URL", "redis://localhost:6379")


def _get_redis():  # type: ignore[return]
    """Return a Redis client or None if unavailable (import-safe, lazy)."""
    try:
        import redis  # type: ignore[import-untyped]

        client = redis.Redis.from_url(_REDIS_URL, socket_connect_timeout=1, decode_responses=True)
        client.ping()  # fast liveness check
        return client
    except Exception:  # noqa: BLE001
        return None


def _check_and_record_spike(ip: str) -> bool:
    """Increment per-IP auth-failure counter in Redis; return True if threshold exceeded.

    Uses a fixed-window approach: one Redis key per IP with AEGIS_SPIKE_WINDOW TTL.
    The TTL is set only on the first increment so the window anchors to the first
    failure, not the last.
    """
    redis_url = os.environ.get("AEGIS_REDIS_URL", "redis://localhost:6379")
    try:
        import redis as redis_lib  # type: ignore[import-untyped]

        r = redis_lib.Redis.from_url(
            redis_url, socket_connect_timeout=1, decode_responses=True
        )
        key = f"aegis:auth_fail:{ip}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, _SPIKE_WINDOW_SECONDS)
        r.close()
        return int(count) >= _SPIKE_THRESHOLD
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Public logging functions
# ---------------------------------------------------------------------------


def log_auth_failure(
    *,
    ip: str = "unknown",
    actor: str = "anonymous",
    reason: str,
    correlation_id: str | None = None,
) -> None:
    """Emit ``security_event=auth_failure`` and trigger spike detection.

    Also fires ``security_event=spike_alert`` at CRITICAL if the per-IP failure
    count in Redis reaches AEGIS_SPIKE_THRESHOLD within the rolling window.
    """
    _SEC_LOG.warning(
        "security_event=auth_failure",
        security_event="auth_failure",
        ip=ip,
        actor=actor,
        reason=reason,
        correlation_id=correlation_id,
    )

    if _check_and_record_spike(ip):
        _SEC_LOG.critical(
            "security_event=spike_alert",
            security_event="spike_alert",
            ip=ip,
            threshold=_SPIKE_THRESHOLD,
            window_seconds=_SPIKE_WINDOW_SECONDS,
            correlation_id=correlation_id,
        )


def log_permission_denied(
    *,
    ip: str = "unknown",
    actor: str = "anonymous",
    resource: str | None = None,
    correlation_id: str | None = None,
) -> None:
    """Emit ``security_event=permission_denied`` (HTTP 403 / ownership violation)."""
    _SEC_LOG.warning(
        "security_event=permission_denied",
        security_event="permission_denied",
        ip=ip,
        actor=actor,
        resource=resource,
        correlation_id=correlation_id,
    )


def log_rate_limit_hit(
    *,
    ip: str = "unknown",
    actor: str = "anonymous",
    correlation_id: str | None = None,
) -> None:
    """Emit ``security_event=rate_limit_hit`` (HTTP 429)."""
    _SEC_LOG.warning(
        "security_event=rate_limit_hit",
        security_event="rate_limit_hit",
        ip=ip,
        actor=actor,
        correlation_id=correlation_id,
    )
