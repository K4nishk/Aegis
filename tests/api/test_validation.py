"""tests/api/test_validation.py — SEC-2 / KCH-18: server-side schema validation.

AC: every route rejects hostile/extra-field payloads with HTTP 422.
    Price, role, and permission fields are never accepted from the client.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from api.app import create_app


@pytest.fixture()
def client():
    os.environ.pop("DATABASE_URL", None)
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# POST /scans — hostile payloads
# ---------------------------------------------------------------------------


class TestPostScansValidation:
    def test_extra_field_rejected(self, client):
        """Extra field 'role' must be rejected with 422 (whitelist enforced)."""
        resp = client.post(
            "/scans",
            json={"mcp_json": {}, "label": "ok", "role": "admin"},
        )
        assert resp.status_code == 422

    def test_price_injection_rejected(self, client):
        """A client-supplied 'price' field must never be accepted."""
        resp = client.post(
            "/scans",
            json={"mcp_json": {}, "price": 0},
        )
        assert resp.status_code == 422

    def test_permission_injection_rejected(self, client):
        """A client-supplied 'permission' field must be rejected."""
        resp = client.post(
            "/scans",
            json={"mcp_json": {}, "permission": "superuser"},
        )
        assert resp.status_code == 422

    def test_owner_id_injection_rejected(self, client):
        """Client must not be able to override owner_id."""
        resp = client.post(
            "/scans",
            json={"mcp_json": {}, "owner_id": "00000000-0000-0000-0000-000000000001"},
        )
        assert resp.status_code == 422

    def test_missing_mcp_json_rejected(self, client):
        """mcp_json is required; omitting it must return 422."""
        resp = client.post("/scans", json={"label": "no-mcp"})
        assert resp.status_code == 422

    def test_mcp_json_wrong_type_rejected(self, client):
        """mcp_json must be an object; a string must return 422."""
        resp = client.post("/scans", json={"mcp_json": "not-a-dict"})
        assert resp.status_code == 422

    def test_label_too_long_rejected(self, client):
        """label exceeding 256 chars must return 422."""
        resp = client.post(
            "/scans",
            json={"mcp_json": {}, "label": "x" * 257},
        )
        assert resp.status_code == 422

    def test_valid_minimal_request_accepted(self, client):
        """Baseline: a valid minimal payload must be accepted (201)."""
        resp = client.post("/scans", json={"mcp_json": {}})
        assert resp.status_code == 201

    def test_valid_full_request_accepted(self, client):
        """Baseline: valid payload with both fields must be accepted (201)."""
        resp = client.post(
            "/scans",
            json={"mcp_json": {}, "label": "test-label"},
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# POST /gate — hostile payloads
# ---------------------------------------------------------------------------


class TestPostGateValidation:
    def test_extra_field_rejected(self, client):
        """Extra field must be rejected with 422."""
        resp = client.post(
            "/gate",
            json={
                "scan_id": "00000000-0000-0000-0000-000000000001",
                "min_score": 70,
                "role": "admin",
            },
        )
        assert resp.status_code == 422

    def test_score_override_field_rejected(self, client):
        """Client must not supply a 'score' override field."""
        resp = client.post(
            "/gate",
            json={
                "scan_id": "00000000-0000-0000-0000-000000000001",
                "score": 100,
            },
        )
        assert resp.status_code == 422

    def test_min_score_below_zero_rejected(self, client):
        """min_score < 0 must return 422."""
        resp = client.post(
            "/gate",
            json={"scan_id": "00000000-0000-0000-0000-000000000001", "min_score": -1},
        )
        assert resp.status_code == 422

    def test_min_score_above_100_rejected(self, client):
        """min_score > 100 must return 422."""
        resp = client.post(
            "/gate",
            json={"scan_id": "00000000-0000-0000-0000-000000000001", "min_score": 101},
        )
        assert resp.status_code == 422

    def test_invalid_scan_id_uuid_rejected(self, client):
        """Non-UUID scan_id must return 422."""
        resp = client.post(
            "/gate",
            json={"scan_id": "not-a-uuid", "min_score": 70},
        )
        assert resp.status_code == 422

    def test_missing_scan_id_rejected(self, client):
        """Omitting scan_id must return 422."""
        resp = client.post("/gate", json={"min_score": 70})
        assert resp.status_code == 422

    def test_valid_gate_request_processed(self, client):
        """Baseline: valid gate payload reaches the handler (503 no DB, not 422)."""
        resp = client.post(
            "/gate",
            json={
                "scan_id": "00000000-0000-0000-0000-000000000001",
                "min_score": 70,
            },
        )
        # Without DB the handler returns 503, not 422 — schema was accepted
        assert resp.status_code == 503
