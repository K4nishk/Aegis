"""api/deps.py — FastAPI dependencies: DB connection, API-key auth (KCH-11)."""

from __future__ import annotations

import os
from collections.abc import Generator
from typing import Any

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_db() -> Generator[Any | None, None, None]:
    """Yield a psycopg2 connection or None when DATABASE_URL is unset."""
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
# Auth — ADR-5: static API key via X-API-Key header
# ---------------------------------------------------------------------------


async def require_api_key(
    key: str | None = Security(_api_key_header),
) -> str | None:
    """Check X-API-Key against AEGIS_API_KEY env var.

    If AEGIS_API_KEY is not set the check is skipped (dev / test mode).
    """
    expected = os.environ.get("AEGIS_API_KEY")
    if expected and key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key
