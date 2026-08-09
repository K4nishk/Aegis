"""tests/api/test_authorization.py — KCH-17: RLS + per-route ownership tests.

Acceptance criterion: log in as user A, request user B's row by ID →
  fails at BOTH the API layer (owner_id filter) and the DB layer (RLS policy).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "mcp"
_KNOWN_BAD = _FIXTURES / "known_bad.json"

# Two stable user UUIDs used throughout these tests
_USER_A = "aaaaaaaa-0000-4000-8000-000000000001"
_USER_B = "bbbbbbbb-0000-4000-8000-000000000002"

_SIMPLE_MCP = {"mcpServers": {}}


def _client(dsn: str, user_id: str):
    """Create a TestClient with DATABASE_URL and AEGIS_USER_ID set.

    Uses AEGIS_DEV_NO_AUTH=1 so tests don't need a key header (KCH-30).
    """
    from fastapi.testclient import TestClient

    from api.app import create_app

    os.environ["DATABASE_URL"] = dsn
    os.environ["AEGIS_USER_ID"] = user_id
    os.environ["AEGIS_DEV_NO_AUTH"] = "1"
    os.environ.pop("AEGIS_API_KEY", None)
    app = create_app()
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _post_scan(client, mcp_json: dict | None = None) -> str:
    payload = mcp_json or _SIMPLE_MCP
    resp = client.post("/scans", json={"mcp_json": payload, "label": "authtest"})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Unit: get_current_user resolution (no DB needed)
# ---------------------------------------------------------------------------


class TestGetCurrentUser:
    """get_current_user key-to-UUID mapping logic."""

    def test_anon_uuid_in_dev_mode_no_key(self):
        """With AEGIS_DEV_NO_AUTH=1 and no key/override → _ANON_USER_ID (KCH-30)."""
        import asyncio

        from api.deps import _ANON_USER_ID, get_current_user

        os.environ["AEGIS_DEV_NO_AUTH"] = "1"
        os.environ.pop("AEGIS_USER_ID", None)
        os.environ.pop("AEGIS_API_KEY", None)
        try:
            result = asyncio.run(get_current_user(None))
            assert result == _ANON_USER_ID
        finally:
            del os.environ["AEGIS_DEV_NO_AUTH"]

    def test_aegis_user_id_env_overrides_in_dev_mode(self):
        """AEGIS_USER_ID override is respected in dev mode (KCH-30)."""
        import asyncio

        from api.deps import get_current_user

        os.environ["AEGIS_DEV_NO_AUTH"] = "1"
        os.environ["AEGIS_USER_ID"] = _USER_A
        try:
            result = asyncio.run(get_current_user(None))
            assert result == uuid.UUID(_USER_A)
        finally:
            os.environ.pop("AEGIS_DEV_NO_AUTH", None)
            os.environ.pop("AEGIS_USER_ID", None)

    def test_key_derives_deterministic_uuid(self):
        """Key → deterministic UUID via SHA-256 when AEGIS_API_KEY matches (KCH-17)."""
        import asyncio
        import hashlib

        from api.deps import get_current_user

        key = "test-key-xyz"
        os.environ["AEGIS_API_KEY"] = key
        os.environ.pop("AEGIS_USER_ID", None)
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)
        try:
            result = asyncio.run(get_current_user(key))
            expected_bytes = hashlib.sha256(key.encode()).digest()[:16]
            assert result == uuid.UUID(bytes=expected_bytes)
        finally:
            del os.environ["AEGIS_API_KEY"]

    def test_wrong_api_key_raises_401(self):
        import asyncio

        from fastapi import HTTPException

        from api.deps import get_current_user

        os.environ["AEGIS_API_KEY"] = "correct-key"
        os.environ.pop("AEGIS_DEV_NO_AUTH", None)
        try:
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(get_current_user("wrong-key"))
            assert exc_info.value.status_code == 401
        finally:
            del os.environ["AEGIS_API_KEY"]


# ---------------------------------------------------------------------------
# Integration: AC — user A creates, user B is denied (both layers)
# ---------------------------------------------------------------------------


class TestOwnershipIsolation:
    """Core KCH-17 AC: cross-user row access is denied at both API and DB layers."""

    @pytest.fixture(autouse=True)
    def _cleanup_env(self):
        """Ensure env vars are clean before and after each test."""
        for k in ("AEGIS_USER_ID", "AEGIS_API_KEY", "DATABASE_URL", "AEGIS_DEV_NO_AUTH"):
            os.environ.pop(k, None)
        yield
        for k in ("AEGIS_USER_ID", "AEGIS_API_KEY", "DATABASE_URL", "AEGIS_DEV_NO_AUTH"):
            os.environ.pop(k, None)

    def test_get_scan_cross_user_returns_404(self, test_db_dsn):
        """User B cannot GET a scan created by user A → 404."""
        client_a = _client(test_db_dsn, _USER_A)
        scan_id = _post_scan(client_a)

        # Confirm user A can read their own scan
        resp_a = client_a.get(f"/scans/{scan_id}")
        assert resp_a.status_code == 200

        # User B tries to read the same scan
        client_b = _client(test_db_dsn, _USER_B)
        resp_b = client_b.get(f"/scans/{scan_id}")
        assert resp_b.status_code == 404, (
            f"Expected 404 for cross-user access; got {resp_b.status_code}: {resp_b.text}"
        )

    def test_report_cross_user_returns_404(self, test_db_dsn):
        """User B cannot GET /report for a scan created by user A."""
        client_a = _client(test_db_dsn, _USER_A)
        scan_id = _post_scan(client_a)

        client_b = _client(test_db_dsn, _USER_B)
        resp = client_b.get(f"/scans/{scan_id}/report")
        assert resp.status_code == 404

    def test_aibom_cross_user_returns_404(self, test_db_dsn):
        """User B cannot GET /aibom for a scan created by user A."""
        import json

        client_a = _client(test_db_dsn, _USER_A)
        mcp_json = json.loads(_KNOWN_BAD.read_text())
        scan_id = _post_scan(client_a, mcp_json)

        client_b = _client(test_db_dsn, _USER_B)
        resp = client_b.get(f"/scans/{scan_id}/aibom")
        assert resp.status_code == 404

    def test_gate_cross_user_returns_404(self, test_db_dsn):
        """User B cannot POST /gate for a scan created by user A."""
        client_a = _client(test_db_dsn, _USER_A)
        scan_id = _post_scan(client_a)

        client_b = _client(test_db_dsn, _USER_B)
        resp = client_b.post("/gate", json={"scan_id": scan_id, "min_score": 0})
        assert resp.status_code == 404

    def test_users_see_only_own_scans_via_rls(self, test_db_dsn):
        """RLS layer: querying scan_runs via aegis_app role with wrong app.user_id returns 0 rows.

        Superusers bypass RLS even with FORCE ROW LEVEL SECURITY; the app role
        (aegis_app) is a non-superuser and is therefore subject to RLS policies.
        In production, the application connects as aegis_app so RLS is enforced.
        """
        import psycopg2  # type: ignore[import-untyped]

        # Create scan as user A via API
        client_a = _client(test_db_dsn, _USER_A)
        scan_id = _post_scan(client_a)

        conn = psycopg2.connect(test_db_dsn)
        try:
            # Switch to non-superuser role so RLS policies are enforced
            with conn.cursor() as cur:
                cur.execute("SET ROLE aegis_app")

            # With user A context → aegis_app subject to RLS should see the row
            with conn.cursor() as cur:
                cur.execute("SET LOCAL app.user_id = %s", (_USER_A,))
                cur.execute("SELECT id FROM scan_runs WHERE id = %s", (scan_id,))
                row = cur.fetchone()
            assert row is not None, "User A should see their own scan via RLS"

            conn.rollback()  # Reset SET LOCAL and SET ROLE

            # Switch to non-superuser role again for the B context test
            with conn.cursor() as cur:
                cur.execute("SET ROLE aegis_app")

            # With user B context → RLS must hide the row
            with conn.cursor() as cur:
                cur.execute("SET LOCAL app.user_id = %s", (_USER_B,))
                cur.execute("SELECT id FROM scan_runs WHERE id = %s", (scan_id,))
                row = cur.fetchone()
            assert row is None, "RLS should hide user A's scan when app.user_id = user B"
            conn.rollback()
        finally:
            conn.close()

    def test_owner_id_persisted_correctly(self, test_db_dsn):
        """scan_runs.owner_id is stored as the resolved user UUID."""
        import psycopg2  # type: ignore[import-untyped]

        client_a = _client(test_db_dsn, _USER_A)
        scan_id = _post_scan(client_a)

        conn = psycopg2.connect(test_db_dsn)
        try:
            # Superuser connection bypasses RLS — read owner_id directly
            with conn.cursor() as cur:
                cur.execute("SELECT owner_id FROM scan_runs WHERE id = %s", (scan_id,))
                row = cur.fetchone()
            assert row is not None
            assert str(row[0]) == _USER_A
            conn.rollback()
        finally:
            conn.close()

    def test_user_a_cannot_see_user_b_nodes_via_rls(self, test_db_dsn):
        """RLS on tool_graph_nodes: aegis_app role with user A context sees 0 nodes from user B's scan."""
        import json

        import psycopg2  # type: ignore[import-untyped]

        mcp_json = json.loads(_KNOWN_BAD.read_text())
        client_b = _client(test_db_dsn, _USER_B)
        b_scan_id = _post_scan(client_b, mcp_json)

        conn = psycopg2.connect(test_db_dsn)
        try:
            # Use non-superuser role so RLS policies are enforced
            with conn.cursor() as cur:
                cur.execute("SET ROLE aegis_app")

            # User A context: should see 0 nodes from user B's scan
            with conn.cursor() as cur:
                cur.execute("SET LOCAL app.user_id = %s", (_USER_A,))
                cur.execute(
                    "SELECT COUNT(*) FROM tool_graph_nodes WHERE scan_run_id = %s",
                    (b_scan_id,),
                )
                count = cur.fetchone()[0]
            assert count == 0, f"RLS should hide user B's nodes from user A; found {count}"
            conn.rollback()
        finally:
            conn.close()
