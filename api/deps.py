"""api/deps.py — FastAPI dependencies: DB connection, API-key auth (KCH-11/KCH-17/KCH-30/KCH-21)."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import uuid
from collections.abc import Generator
from typing import Any

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Sentinel UUID used in dev/anonymous mode (AEGIS_DEV_NO_AUTH=1 only).
_ANON_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def _key_to_user_id(key: str) -> uuid.UUID:
    """Deterministically map an API key to a UUID via SHA-256 (first 16 bytes)."""
    raw = hashlib.sha256(key.encode()).digest()[:16]
    return uuid.UUID(bytes=raw)


def check_auth_config() -> None:
    """Fail closed: raise RuntimeError if auth is misconfigured.

    Called at app startup (create_app). If AEGIS_API_KEY is not set and
    AEGIS_DEV_NO_AUTH is not '1', the app refuses to start rather than
    silently serving unauthenticated traffic (KCH-30).
    """
    api_key = os.environ.get("AEGIS_API_KEY")
    dev_no_auth = os.environ.get("AEGIS_DEV_NO_AUTH") == "1"
    if not api_key and not dev_no_auth:
        raise RuntimeError(
            "AEGIS_API_KEY is not set. "
            "Set it to a secret value, or set AEGIS_DEV_NO_AUTH=1 "
            "to run without auth locally (never in production)."
        )


# ---------------------------------------------------------------------------
# Auth + user resolution — KCH-17 / KCH-30
# ---------------------------------------------------------------------------


async def get_current_user(
    key: str | None = Security(_api_key_header),  # noqa: B008
) -> uuid.UUID:
    """Validate the API key and resolve it to an owner UUID.

    Resolution order:
    1. AEGIS_DEV_NO_AUTH=1 → skip key check; use AEGIS_USER_ID or _ANON_USER_ID.
    2. AEGIS_API_KEY set, key matches (constant-time compare) → proceed.
    3. Key missing or wrong → 401 (security event logged).
    4. AEGIS_API_KEY unset and dev mode off → 401 (startup check should catch this first).

    IP and correlation_id are read from per-request contextvars set by
    CorrelationIdMiddleware (KCH-21).  When called directly in tests the
    contextvars fall back to their defaults ("unknown", None).
    """
    from api.security_events import (
        get_request_correlation_id,
        get_request_ip,
        log_auth_failure,
    )

    dev_no_auth = os.environ.get("AEGIS_DEV_NO_AUTH") == "1"
    configured_key = os.environ.get("AEGIS_API_KEY")

    ip = get_request_ip()
    correlation_id = get_request_correlation_id()
    actor = (key or "")[:64] or "anonymous"

    if not dev_no_auth:
        if not configured_key:
            # Misconfiguration: startup check should have prevented this.
            _log.warning("security_event=auth_failure reason=no_key_configured")
            log_auth_failure(ip=ip, actor=actor, reason="no_key_configured", correlation_id=correlation_id)
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        if not secrets.compare_digest(key or "", configured_key):
            _log.warning(
                "security_event=auth_failure reason=bad_key key_present=%s",
                key is not None,
            )
            log_auth_failure(
                ip=ip,
                actor=actor,
                reason="bad_key",
                correlation_id=correlation_id,
            )
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    # Explicit user override (for single-key deployments and tests in dev mode)
    override = os.environ.get("AEGIS_USER_ID")
    if override:
        return uuid.UUID(override)

    if key:
        return _key_to_user_id(key)

    # dev_no_auth=True with no key and no AEGIS_USER_ID → anonymous sentinel
    return _ANON_USER_ID


# ---------------------------------------------------------------------------
# DB — with RLS user context set (KCH-17)
# ---------------------------------------------------------------------------


def get_authed_db(
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> Generator[Any | None, None, None]:
    """Yield a psycopg2 connection with ``SET LOCAL app.user_id`` applied.

    Setting app.user_id at transaction start activates the RLS policies added
    in V5__add_owner_rls.up.sql so the DB itself enforces ownership isolation
    in addition to the API-level owner_id filter on each query.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        yield None
        return
    try:
        import psycopg2  # type: ignore[import-untyped]
    except ImportError:
        yield None
        return

    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            # SET LOCAL scopes the setting to the current transaction.
            cur.execute("SET LOCAL app.user_id = %s", (str(user_id),))
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Legacy alias — kept so existing imports don't break during the transition.
# New code should use get_authed_db.
# ---------------------------------------------------------------------------


def get_db() -> Generator[Any | None, None, None]:
    """Yield a plain psycopg2 connection (no RLS user context).

    Deprecated: use get_authed_db for all authenticated routes.
    Retained for backward compatibility with any non-route callers.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        yield None
        return
    try:
        import psycopg2  # type: ignore[import-untyped]
    except ImportError:
        yield None
        return

    conn = psycopg2.connect(dsn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Legacy auth dependency — kept for backward compatibility.
# ---------------------------------------------------------------------------


async def require_api_key(
    key: str | None = Security(_api_key_header),  # noqa: B008
) -> str | None:
    """Check X-API-Key against AEGIS_API_KEY env var.

    Deprecated: prefer get_current_user which also returns the owner UUID.
    Delegates to get_current_user so auth logic stays in one place (KCH-30).
    """
    await get_current_user(key)
    return key
