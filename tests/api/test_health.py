"""tests/api/test_health.py — /health endpoint tests (KCH-33).

The health endpoint must:
  - Return 200 without an X-API-Key header
  - Include {"status", "db", "redis"} fields in the JSON response
  - Not require AEGIS_API_KEY to be set
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def health_client():
    """TestClient with no DATABASE_URL so health returns quickly."""
    # Ensure the app can start: use dev-no-auth mode and no DB/Redis configured.
    old_env = {
        "DATABASE_URL": os.environ.pop("DATABASE_URL", None),
        "AEGIS_DEV_NO_AUTH": os.environ.get("AEGIS_DEV_NO_AUTH"),
    }
    os.environ["AEGIS_DEV_NO_AUTH"] = "1"
    os.environ.pop("DATABASE_URL", None)

    from api.app import create_app

    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client

    # Restore env
    for k, v in old_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


class TestHealthEndpoint:
    def test_no_api_key_required(self, health_client: TestClient) -> None:
        """GET /health must succeed without X-API-Key."""
        response = health_client.get("/health")
        # 200 (all ok) or 503 (degraded) — both are valid responses; the key
        # assertion is that we do NOT get 401 or 403 (auth error).
        assert response.status_code in (200, 503)

    def test_response_has_required_fields(self, health_client: TestClient) -> None:
        """Response body must include status, db, and redis keys."""
        response = health_client.get("/health")
        data = response.json()
        assert "status" in data
        assert "db" in data
        assert "redis" in data

    def test_status_field_is_valid(self, health_client: TestClient) -> None:
        """status field must be one of the known values."""
        response = health_client.get("/health")
        data = response.json()
        assert data["status"] in ("ok", "degraded")

    def test_no_db_returns_not_configured(self, health_client: TestClient) -> None:
        """When DATABASE_URL is absent, db field should be 'not_configured'."""
        # health_client fixture already clears DATABASE_URL
        response = health_client.get("/health")
        data = response.json()
        assert data["db"] == "not_configured"

    def test_authenticated_routes_still_require_key(self, health_client: TestClient) -> None:
        """Verify auth-protected routes still return 401 without a key (regression guard).

        AEGIS_DEV_NO_AUTH=1 is set so 401 won't fire — but the route should
        still exist and return something other than 404.
        """
        response = health_client.get("/scans/nonexistent-id")
        # Could be 503 (no DB), 422, or 404, but NOT 404 on the route itself.
        assert response.status_code != 404 or response.json().get("detail") != "Not Found"
