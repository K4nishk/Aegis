"""api/app.py — FastAPI application factory + CorrelationIdMiddleware (KCH-11)."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from api.routes import router


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Propagate X-Correlation-Id and append an audit_log row for every request."""

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        correlation_id = request.headers.get("X-Correlation-Id") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        request.state.audit_resource_id = None  # routes may overwrite

        response: Response = await call_next(request)
        response.headers["X-Correlation-Id"] = correlation_id

        # Audit log — best-effort, must never break the response
        _write_audit_log(
            method=request.method,
            path=request.url.path,
            actor=request.headers.get("X-API-Key", "anonymous")[:64],
            status_code=response.status_code,
            correlation_id=correlation_id,
            resource_id=getattr(request.state, "audit_resource_id", None),
        )

        return response


def _write_audit_log(
    *,
    method: str,
    path: str,
    actor: str,
    status_code: int,
    correlation_id: str,
    resource_id: str | None,
) -> None:
    """Write a single audit_log row (synchronous psycopg2, best-effort)."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        return
    try:
        import psycopg2  # type: ignore[import-untyped]

        conn = psycopg2.connect(dsn)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_log
                    (ts, actor, action, resource_type, resource_id, new_val)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    _utcnow(),
                    actor,
                    f"{method} {path}",
                    "api_request",
                    resource_id,
                    json.dumps(
                        {"status_code": status_code, "correlation_id": correlation_id}
                    ),
                ),
            )
        conn.close()
    except Exception:
        pass  # audit failure must never surface to callers


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis Security API",
        description=(
            "MCP tool-graph security analysis: posture scoring, trifecta detection, "
            "AI Bill of Materials, and CI/CD gate."
        ),
        version="0.1.0",
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(router)
    return app


app = create_app()
