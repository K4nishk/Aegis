"""tests/api/test_api.py — FastAPI endpoint tests (KCH-11).

Unit tests (no DB) cover analysis correctness.
Integration tests (require local Postgres) cover full 5-endpoint flow.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "mcp"
_KNOWN_BAD = _FIXTURES / "known_bad.json"
_CLAUDE_DESKTOP = _FIXTURES / "claude_desktop.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(dsn: str | None = None) -> TestClient:
    """Create a TestClient with optional DATABASE_URL override."""
    env_patch: dict[str, str] = {}
    if dsn:
        env_patch["DATABASE_URL"] = dsn
    old = {k: os.environ.get(k) for k in env_patch}
    for k, v in env_patch.items():
        os.environ[k] = v
    try:
        app = create_app()
        client = TestClient(app, raise_server_exceptions=True)
    finally:
        for k, old_v in old.items():
            if old_v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old_v
    return client


def _load_mcp(path: Path) -> dict:
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Unit tests — no DB required
# ---------------------------------------------------------------------------


class TestPostScansNoDB:
    """POST /scans works without a database (ephemeral mode)."""

    def setup_method(self):
        os.environ.pop("DATABASE_URL", None)

    def test_known_bad_score_and_trifecta(self):
        """AC: POST /scans on seeded-bad mcp.json → score returned + ≥1 trifecta finding."""
        app = create_app()
        client = TestClient(app)

        mcp_json = _load_mcp(_KNOWN_BAD)
        resp = client.post("/scans", json={"mcp_json": mcp_json, "label": "known_bad"})
        assert resp.status_code == 201, resp.text

        data = resp.json()
        assert "id" in data
        assert data["status"] == "ephemeral"
        assert isinstance(data["score"], int)
        assert 0 <= data["score"] <= 100
        # seeded-bad has all three caps → trifecta path must fire
        assert data["trifecta_finding_count"] >= 1, (
            f"Expected ≥1 trifecta finding on known_bad; got {data['trifecta_finding_count']}"
        )

    def test_score_decremented_for_known_bad(self):
        """Score on known_bad must be well below 100."""
        app = create_app()
        client = TestClient(app)
        mcp_json = _load_mcp(_KNOWN_BAD)
        resp = client.post("/scans", json={"mcp_json": mcp_json})
        assert resp.status_code == 201
        assert resp.json()["score"] < 60

    def test_correlation_id_header_set(self):
        """Response must carry X-Correlation-Id."""
        app = create_app()
        client = TestClient(app)
        mcp_json = _load_mcp(_KNOWN_BAD)
        resp = client.post("/scans", json={"mcp_json": mcp_json})
        assert "x-correlation-id" in resp.headers

    def test_correlation_id_propagated(self):
        """Supplied X-Correlation-Id is echoed back."""
        app = create_app()
        client = TestClient(app)
        mcp_json = _load_mcp(_KNOWN_BAD)
        cid = "test-cid-abc123"
        resp = client.post(
            "/scans",
            json={"mcp_json": mcp_json},
            headers={"X-Correlation-Id": cid},
        )
        assert resp.headers["x-correlation-id"] == cid

    def test_api_key_rejected_when_env_set(self):
        """Requests with wrong API key are rejected 401."""
        os.environ["AEGIS_API_KEY"] = "supersecret"
        try:
            app = create_app()
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/scans", json={"mcp_json": {}})
            assert resp.status_code == 401
        finally:
            del os.environ["AEGIS_API_KEY"]

    def test_api_key_accepted(self):
        """Requests with correct API key are accepted."""
        os.environ["AEGIS_API_KEY"] = "supersecret"
        try:
            app = create_app()
            client = TestClient(app, raise_server_exceptions=False)
            mcp_json = _load_mcp(_KNOWN_BAD)
            resp = client.post(
                "/scans",
                json={"mcp_json": mcp_json},
                headers={"X-API-Key": "supersecret"},
            )
            assert resp.status_code == 201
        finally:
            del os.environ["AEGIS_API_KEY"]

    def test_empty_config_score_below_100(self):
        """Empty MCP config → no_auth + no_ratelimit fire → score 85."""
        app = create_app()
        client = TestClient(app)
        resp = client.post("/scans", json={"mcp_json": {}})
        assert resp.status_code == 201
        assert resp.json()["score"] == 85

    def test_get_scan_without_db_returns_503(self):
        """GET /scans/{id} returns 503 when no DATABASE_URL."""
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/scans/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 503

    def test_openapi_schema_available(self):
        """OpenAPI schema is served at /openapi.json."""
        app = create_app()
        client = TestClient(app)
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        # All 5 endpoints must appear in paths
        paths = schema["paths"]
        assert "/scans" in paths
        assert "/scans/{scan_id}" in paths
        assert "/scans/{scan_id}/report" in paths
        assert "/scans/{scan_id}/aibom" in paths
        assert "/gate" in paths


# ---------------------------------------------------------------------------
# Integration tests — require local Postgres
# ---------------------------------------------------------------------------


class TestFullFlowWithDB:
    """End-to-end tests against a real (scratch) Postgres database."""

    @pytest.fixture(autouse=True)
    def _setup(self, test_db_dsn):
        os.environ["DATABASE_URL"] = test_db_dsn
        yield
        os.environ.pop("DATABASE_URL", None)

    def test_post_scans_persists_and_get_returns_scan(self, test_db_dsn):
        app = create_app()
        client = TestClient(app)

        mcp_json = _load_mcp(_KNOWN_BAD)
        post_resp = client.post("/scans", json={"mcp_json": mcp_json, "label": "db_test"})
        assert post_resp.status_code == 201, post_resp.text
        scan_id = post_resp.json()["id"]
        assert post_resp.json()["status"] == "completed"

        get_resp = client.get(f"/scans/{scan_id}")
        assert get_resp.status_code == 200, get_resp.text
        data = get_resp.json()
        assert data["id"] == scan_id
        assert data["status"] == "completed"
        assert data["score"] == post_resp.json()["score"]

    def test_report_json(self, test_db_dsn):
        app = create_app()
        client = TestClient(app)

        mcp_json = _load_mcp(_KNOWN_BAD)
        scan_id = client.post("/scans", json={"mcp_json": mcp_json}).json()["id"]

        resp = client.get(f"/scans/{scan_id}/report?fmt=json")
        assert resp.status_code == 200
        report = resp.json()
        assert report["scan_id"] == scan_id
        assert "rules" in report
        assert "trifecta_findings" in report
        assert len(report["trifecta_findings"]) >= 1

    def test_report_text(self, test_db_dsn):
        app = create_app()
        client = TestClient(app)

        mcp_json = _load_mcp(_KNOWN_BAD)
        scan_id = client.post("/scans", json={"mcp_json": mcp_json}).json()["id"]

        resp = client.get(f"/scans/{scan_id}/report?fmt=text")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert "Score:" in resp.text

    def test_aibom_returns_components(self, test_db_dsn):
        app = create_app()
        client = TestClient(app)

        mcp_json = _load_mcp(_KNOWN_BAD)
        scan_id = client.post("/scans", json={"mcp_json": mcp_json}).json()["id"]

        resp = client.get(f"/scans/{scan_id}/aibom")
        assert resp.status_code == 200
        bom = resp.json()
        assert bom["scan_id"] == scan_id
        assert len(bom["components"]) >= 1
        # Check component shape
        comp = bom["components"][0]
        assert "node_key" in comp
        assert "tool_name" in comp
        assert "caps" in comp
        assert "security_caps" in comp

    def test_gate_passes_when_score_above_threshold(self, test_db_dsn):
        app = create_app()
        client = TestClient(app)

        # Use a benign config that should score > 0
        mcp_json = _load_mcp(_CLAUDE_DESKTOP)
        scan_id = client.post("/scans", json={"mcp_json": mcp_json}).json()["id"]

        resp = client.post("/gate", json={"scan_id": scan_id, "min_score": 0})
        assert resp.status_code == 200
        result = resp.json()
        assert result["passed"] is True
        assert result["min_score"] == 0

    def test_gate_fails_for_known_bad(self, test_db_dsn):
        app = create_app()
        client = TestClient(app)

        mcp_json = _load_mcp(_KNOWN_BAD)
        post_resp = client.post("/scans", json={"mcp_json": mcp_json}).json()
        scan_id = post_resp["id"]
        score = post_resp["score"]

        # Gate with a threshold higher than the actual score → fail
        resp = client.post("/gate", json={"scan_id": scan_id, "min_score": score + 1})
        assert resp.status_code == 200
        assert resp.json()["passed"] is False

    def test_audit_log_row_written(self, test_db_dsn):
        """Every request writes an audit_log row."""
        import psycopg2  # type: ignore[import-untyped]

        app = create_app()
        client = TestClient(app)
        mcp_json = _load_mcp(_KNOWN_BAD)
        client.post("/scans", json={"mcp_json": mcp_json})

        conn = psycopg2.connect(test_db_dsn)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'POST /scans'")
            count = cur.fetchone()[0]
        conn.close()

        assert count >= 1, "Expected at least one audit_log row for POST /scans"

    def test_get_nonexistent_scan_404(self, test_db_dsn):
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/scans/00000000-0000-0000-0000-000000000099")
        assert resp.status_code == 404
