"""tests/api/test_metrics.py — Tests for GET /metrics (KCH-16).

No-DB tests: always run.  Integration tests: auto-skipped without Postgres.
"""

from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client():
    """Return a TestClient with AEGIS_DEV_NO_AUTH=1 (no DB).

    The conftest autouse fixture already sets AEGIS_DEV_NO_AUTH=1; this helper
    exists so no-DB tests can create a client without boilerplate.
    """
    from fastapi.testclient import TestClient

    from api.app import create_app

    return TestClient(create_app(), raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Q3 (no DB) tests — always run
# ---------------------------------------------------------------------------


class TestQ3NoDB:
    def test_metrics_endpoint_returns_200(self):
        """GET /metrics should succeed even without a DB."""
        client = _client()
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_q3_present(self):
        """Q3 eval metrics must always be present."""
        client = _client()
        data = client.get("/metrics").json()
        assert "q3" in data
        q3 = data["q3"]
        assert "macro_f1" in q3
        assert "macro_precision" in q3
        assert "macro_recall" in q3
        assert "ambiguity_rate" in q3
        assert "per_cap" in q3
        assert isinstance(q3["per_cap"], list)
        assert len(q3["per_cap"]) == 3  # 3 caps

    def test_metrics_q1_q2_none_without_db(self):
        """Q1 and Q2 are None when no database is connected."""
        client = _client()
        data = client.get("/metrics").json()
        assert data["q1"] is None
        assert data["q2"] is None

    def test_q3_macro_f1_above_kill_threshold(self):
        """Macro F1 must be >= 0.70 (KILL gate — equivalent to test_gate_macro_f1_threshold)."""
        client = _client()
        data = client.get("/metrics").json()
        q3 = data["q3"]
        assert q3["macro_f1"] >= 0.70, f"macro_f1={q3['macro_f1']:.3f} is below KILL threshold 0.70"

    def test_q3_ambiguity_below_kill_threshold(self):
        """Ambiguity rate must be <= 0.40 (KILL gate)."""
        client = _client()
        data = client.get("/metrics").json()
        q3 = data["q3"]
        assert q3["ambiguity_rate"] <= 0.40, (
            f"ambiguity_rate={q3['ambiguity_rate']:.3f} exceeds KILL threshold 0.40"
        )

    def test_q3_kill_gates_not_triggered(self):
        """No KILL gate should be triggered given KCH-27 tighten."""
        client = _client()
        data = client.get("/metrics").json()
        q3 = data["q3"]
        assert not q3["any_kill"], f"KILL gate triggered: {q3}"

    def test_q3_seeded_bad_not_missed(self):
        """All seeded-bad tools must be detected."""
        client = _client()
        data = client.get("/metrics").json()
        q3 = data["q3"]
        assert q3["seeded_bad_missed"] == [], f"seeded_bad_missed: {q3['seeded_bad_missed']}"

    def test_q3_per_cap_fields(self):
        """Each per_cap entry must have tp/fp/fn/tn fields."""
        client = _client()
        data = client.get("/metrics").json()
        for cap_entry in data["q3"]["per_cap"]:
            for field in ("cap", "precision", "recall", "f1", "tp", "fp", "fn", "tn"):
                assert field in cap_entry, f"Missing field {field!r} in {cap_entry}"

    def test_metrics_window_days_param(self):
        """window_days query param is reflected in response."""
        client = _client()
        data = client.get("/metrics?window_days=7").json()
        assert data["window_days"] == 7

    def test_metrics_html_format(self):
        """fmt=html returns an HTML response."""
        client = _client()
        resp = client.get("/metrics?fmt=html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Aegis Metrics Review Board" in resp.text
        assert "Q1" in resp.text
        assert "Q2" in resp.text
        assert "Q3" in resp.text

    def test_metrics_html_kill_gates_shown(self):
        """HTML dashboard must surface KILL gate verdicts."""
        client = _client()
        resp = client.get("/metrics?fmt=html")
        assert "KILL" in resp.text or "GO" in resp.text

    def test_metrics_generated_at_present(self):
        """Response includes a generated_at timestamp."""
        client = _client()
        data = client.get("/metrics").json()
        assert "generated_at" in data
        assert data["generated_at"]  # non-empty

    def test_metrics_requires_auth_when_key_set(self, monkeypatch):
        """Without X-API-Key, returns 401 when AEGIS_API_KEY is set."""
        from fastapi.testclient import TestClient

        from api.app import create_app

        monkeypatch.setenv("AEGIS_API_KEY", "secret-test-key")
        monkeypatch.delenv("AEGIS_DEV_NO_AUTH", raising=False)
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/metrics")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Direct unit tests for api.metrics module
# ---------------------------------------------------------------------------


class TestMetricsModule:
    def test_query_q3_returns_dataclass(self):
        """query_q3() returns Q3EvalMetrics with expected fields."""
        from api.metrics import query_q3

        result = query_q3()
        assert hasattr(result, "macro_f1")
        assert hasattr(result, "per_cap")
        assert 0.0 <= result.macro_f1 <= 1.0
        assert 0.0 <= result.ambiguity_rate <= 1.0
        assert result.n_tools > 0

    def test_query_q3_per_cap_three_caps(self):
        """query_q3() returns exactly 3 cap entries."""
        from api.metrics import query_q3

        result = query_q3()
        assert len(result.per_cap) == 3
        cap_names = {c.cap for c in result.per_cap}
        assert cap_names == {"reads_private_data", "sees_untrusted_content", "can_exfiltrate"}


# ---------------------------------------------------------------------------
# Integration tests (real Postgres)
# ---------------------------------------------------------------------------


class TestMetricsIntegration:
    """Requires Postgres — auto-skipped without a DB in conftest.test_db_dsn."""

    @pytest.fixture(autouse=True)
    def _set_db_url(self, test_db_dsn):
        """Set DATABASE_URL for every test in this class."""
        os.environ["DATABASE_URL"] = test_db_dsn
        yield
        os.environ.pop("DATABASE_URL", None)

    def test_q1_q2_present_with_db(self):
        """With a DB, Q1 and Q2 are populated (even if empty)."""
        resp = _client().get("/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["q1"] is not None
        assert data["q2"] is not None

    def test_q1_structure(self):
        """Q1 returns all expected fields with valid types."""
        data = _client().get("/metrics").json()
        q1 = data["q1"]
        assert isinstance(q1["total_scans"], int)
        assert isinstance(q1["scans_with_trifecta"], int)
        assert isinstance(q1["pct_with_trifecta"], float)
        assert isinstance(q1["total_trifecta_findings"], int)
        assert isinstance(q1["avg_findings_per_scan"], float)
        # invariants
        assert q1["scans_with_trifecta"] <= q1["total_scans"]
        assert q1["total_trifecta_findings"] >= 0

    def test_q2_structure(self):
        """Q2 returns all expected fields with valid types."""
        data = _client().get("/metrics").json()
        q2 = data["q2"]
        assert isinstance(q2["scan_count"], int)
        assert isinstance(q2["avg_score"], float | int)
        assert isinstance(q2["daily"], list)
        assert q2["window_days"] == 30

    def test_q1_q2_after_scan(self):
        """After posting a scan, Q1 total_scans increments and Q2 avg_score reflects it."""
        client = _client()
        mcp_json = {
            "mcpServers": {
                "test_server": {
                    "command": "node",
                    "args": ["server.js"],
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read a local file from disk",
                        }
                    ],
                }
            }
        }
        post_resp = client.post("/scans", json={"mcp_json": mcp_json, "label": "metrics-test"})
        assert post_resp.status_code == 201

        data = client.get("/metrics").json()
        assert data["q1"]["total_scans"] >= 1
        assert data["q2"]["scan_count"] >= 1
        assert data["q2"]["avg_score"] >= 0

    def test_html_format_with_db(self):
        """fmt=html with DB returns HTML that includes Q1 data."""
        resp = _client().get("/metrics?fmt=html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Total Scans" in resp.text
        assert "Avg Score" in resp.text
