"""api/app.py — FastAPI application factory + CorrelationIdMiddleware (KCH-11/KCH-30/KCH-21)."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from api.deps import check_auth_config
from api.logging_config import configure_structlog
from api.routes import router
from api.security_events import set_request_context


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _client_ip(request: Request) -> str:
    """Extract the real client IP (X-Forwarded-For first, then direct peer)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Propagate X-Correlation-Id, capture client IP, and write an audit_log row."""

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        correlation_id = request.headers.get("X-Correlation-Id") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        client_ip = _client_ip(request)
        request.state.client_ip = client_ip
        request.state.audit_resource_id = None  # routes may overwrite

        # Propagate request context to auth dependencies via contextvars.
        set_request_context(ip=client_ip, correlation_id=correlation_id)

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


def _init_sentry() -> None:
    """Initialise Sentry if SENTRY_DSN is set (KCH-21).

    Skipped silently when the env var is absent so local dev / CI work without
    a real Sentry project.  In production the DSN must be injected via the
    deployment environment (EC2 user-data, ECS task definition, etc.).
    """
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration

        sentry_sdk.init(
            dsn=dsn,
            integrations=[StarletteIntegration(), FastApiIntegration()],
            # Only send errors (not transactions) unless explicitly configured.
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0")),
            environment=os.environ.get("AEGIS_ENV", "production"),
        )
    except Exception:  # noqa: BLE001
        pass  # Sentry init failure must never prevent the API from starting.


@asynccontextmanager
async def _lifespan(app: FastAPI):  # noqa: ARG001
    """Fail closed at startup: refuse to serve if auth is misconfigured (KCH-30).

    Also initialises structlog and Sentry (KCH-21).
    """
    configure_structlog()
    _init_sentry()
    check_auth_config()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis Security API",
        description=(
            "MCP tool-graph security analysis: posture scoring, trifecta detection, "
            "AI Bill of Materials, and CI/CD gate."
        ),
        version="0.1.0",
        lifespan=_lifespan,
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.include_router(router)
    return app


app = create_app()
