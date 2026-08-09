"""api/deps.py — FastAPI dependencies: DB connection, API-key auth (KCH-11/KCH-17)."""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Generator
from typing import Any

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Sentinel UUID used in dev/anonymous mode (no API key, no AEGIS_USER_ID).
_ANON_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def _key_to_user_id(key: str) -> uuid.UUID:
    """Deterministically map an API key to a UUID via SHA-256 (first 16 bytes)."""
    raw = hashlib.sha256(key.encode()).digest()[:16]
    return uuid.UUID(bytes=raw)


# ---------------------------------------------------------------------------
# Auth + user resolution — KCH-17
# ---------------------------------------------------------------------------


async def get_current_user(
    key: str | None = Security(_api_key_header),  # noqa: B008
) -> uuid.UUID:
    """Validate the API key and resolve it to an owner UUID.

    Resolution order:
    1. If AEGIS_API_KEY is set and the provided key doesn't match → 401.
    2. If AEGIS_USER_ID env var is set → use that UUID (useful in tests and
       single-key deployments where one canonical user is configured).
    3. Otherwise derive a UUID from the key via SHA-256 (deterministic, no DB lookup).
    4. No key at all → anonymous sentinel UUID (dev mode when AEGIS_API_KEY unset).
    """
    expected = os.environ.get("AEGIS_API_KEY")
    if expected and key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    # Explicit user override (for tests and single-key deployments)
    override = os.environ.get("AEGIS_USER_ID")
    if override:
        return uuid.UUID(override)

    if key:
        return _key_to_user_id(key)

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

    If AEGIS_API_KEY is not set the check is skipped (dev / test mode).
    Deprecated: prefer get_current_user which also returns the owner UUID.
    """
    expected = os.environ.get("AEGIS_API_KEY")
    if expected and key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key
