"""tests/api/test_gate.py — CI gate tests (KCH-13).

No-DB tests (TestGatePrerequisitesNoDB) run in CI without Postgres.
Integration tests (TestGateIntegration) require local Postgres (auto-skipped).

AC: PR introducing a trifecta is blocked; green otherwise.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analyzer.posture import score_posture
from analyzer.trifecta import analyze_trifecta
from api.app import create_app
from parser.mcp import parse_mcp_config

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "mcp"
_KNOWN_BAD = _FIXTURES / "known_bad.json"
_GOLD_LABELS = Path(__file__).parents[1] / "eval_gold" / "gold_labels.json"

# A minimal clean config: pure math tools, no privacy/network/exfil keywords.
# Score = 100 - no_auth(10) - no_ratelimit(5) = 85; no trifecta path.
_CLEAN_MCP: dict = {
    "mcpServers": {
        "calculator": {
            "command": "node",
            "args": ["calc-server"],
            "tools": [
                {
                    "name": "add",
                    "description": "Add two numbers and return the sum.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"},
                        },
                        "required": ["a", "b"],
                    },
                },
                {
                    "name": "multiply",
                    "description": "Multiply two numbers and return the product.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"},
                        },
                        "required": ["a", "b"],
                    },
                },
            ],
        }
    }
}


def _load_mcp(path: Path) -> dict:
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# No-DB tests: verify trifecta detection + score thresholds
# ---------------------------------------------------------------------------


class TestGatePrerequisitesNoDB:
    """Gate prerequisite checks via direct analysis (no DB, no HTTP required)."""

    def _analyze_path(self, path: Path):
        mcp_json = _load_mcp(path)
        graph = parse_mcp_config(mcp_json)
        trifecta = analyze_trifecta(graph)
        posture = score_posture(graph, trifecta)
        return graph, trifecta, posture

    def _analyze_dict(self, mcp_json: dict):
        graph = parse_mcp_config(mcp_json)
        trifecta = analyze_trifecta(graph)
        posture = score_posture(graph, trifecta)
        return graph, trifecta, posture

    def test_known_bad_has_trifecta_finding(self):
        """known_bad config must have at least one trifecta path finding."""
        _, trifecta, _ = self._analyze_path(_KNOWN_BAD)
        assert len(trifecta.findings) >= 1, (
            f"Expected >=1 trifecta finding on known_bad; got {len(trifecta.findings)}"
        )

    def test_known_bad_score_below_gate_threshold(self):
        """known_bad score must be < 70 so the default gate blocks it."""
        _, _, posture = self._analyze_path(_KNOWN_BAD)
        assert posture.score < 70, (
            f"known_bad scored {posture.score}; expected < 70 so gate blocks"
        )

    def test_known_bad_triggers_trifecta_rule(self):
        """known_bad must trigger the trifecta_path posture rule."""
        _, _, posture = self._analyze_path(_KNOWN_BAD)
        assert "trifecta_path" in posture.triggered_rules, (
            f"trifecta_path not in triggered_rules: {posture.triggered_rules}"
        )

    def test_clean_config_no_trifecta_finding(self):
        """Clean math-only config must have zero trifecta path findings."""
        _, trifecta, _ = self._analyze_dict(_CLEAN_MCP)
        assert len(trifecta.findings) == 0, (
            f"Expected 0 trifecta findings on clean config; got {len(trifecta.findings)}"
        )

    def test_clean_config_score_passes_gate(self):
        """Clean config score must be >= 70 so the default gate passes it."""
        _, _, posture = self._analyze_dict(_CLEAN_MCP)
        assert posture.score >= 70, (
            f"Clean config scored {posture.score}; expected >= 70"
        )


# ---------------------------------------------------------------------------
# Eval harness kill gates (no DB)
# ---------------------------------------------------------------------------


def test_gate_macro_f1_threshold():
    """CI kill gate: macro F1 of trifecta classifier must be >= 0.70."""
    from tests.eval_gold.eval_metrics import build_tool_nodes, load_gold_labels, run_eval

    entries = load_gold_labels(_GOLD_LABELS)
    nodes = build_tool_nodes(entries, _FIXTURES)
    report = run_eval(entries, nodes)
    assert not report.kill_f1, (
        f"Macro F1 {report.macro_f1:.1%} < 70% — CI gate FAIL\n"
        + "\n".join(report.summary_lines())
    )


def test_gate_seeded_bad_not_missed():
    """CI kill gate: all seeded-bad tools must be detected by the classifier."""
    from tests.eval_gold.eval_metrics import build_tool_nodes, load_gold_labels, run_eval

    entries = load_gold_labels(_GOLD_LABELS)
    nodes = build_tool_nodes(entries, _FIXTURES)
    report = run_eval(entries, nodes)
    assert not report.kill_seeded_bad, (
        "Seeded-bad tools missed by classifier:\n"
        + "\n".join(f"  {m}" for m in report.seeded_bad_missed)
    )


# ---------------------------------------------------------------------------
# Integration tests — require Postgres (auto-skipped without DB)
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_client(test_db_dsn: str):
    """TestClient backed by a real scratch Postgres DB."""
    os.environ["DATABASE_URL"] = test_db_dsn
    app = create_app()
    client = TestClient(app, raise_server_exceptions=True)
    yield client
    os.environ.pop("DATABASE_URL", None)


def _scan_with_client(client: TestClient, fixture: Path | dict) -> dict:
    mcp_json = _load_mcp(fixture) if isinstance(fixture, Path) else fixture
    resp = client.post("/scans", json={"mcp_json": mcp_json})
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestGateIntegration:
    """POST /gate integration tests against a real Postgres database."""

    def test_trifecta_blocks_gate(self, db_client: TestClient):
        """known_bad -> trifecta fires -> gate passed=False at default threshold."""
        scan = _scan_with_client(db_client, _KNOWN_BAD)
        assert scan["trifecta_finding_count"] >= 1

        resp = db_client.post("/gate", json={"scan_id": scan["id"], "min_score": 70})
        assert resp.status_code == 200
        result = resp.json()
        assert result["passed"] is False, (
            f"Gate should block known_bad (score={result['score']})"
        )
        assert "trifecta_path" in result["triggered_rules"]

    def test_clean_config_passes_gate(self, db_client: TestClient):
        """claude_desktop -> no trifecta -> gate passed=True at default threshold."""
        scan = _scan_with_client(db_client, _CLEAN_MCP)

        resp = db_client.post("/gate", json={"scan_id": scan["id"], "min_score": 70})
        assert resp.status_code == 200
        result = resp.json()
        assert result["passed"] is True, (
            f"Gate should pass claude_desktop (score={result['score']})"
        )

    def test_gate_respects_min_score_zero(self, db_client: TestClient):
        """Any completed scan passes when min_score=0."""
        scan = _scan_with_client(db_client, _KNOWN_BAD)
        resp = db_client.post("/gate", json={"scan_id": scan["id"], "min_score": 0})
        assert resp.status_code == 200
        assert resp.json()["passed"] is True

    def test_gate_respects_min_score_max(self, db_client: TestClient):
        """No real config achieves score=100 (at least no_auth+no_ratelimit fire)."""
        scan = _scan_with_client(db_client, _CLEAN_MCP)
        resp = db_client.post("/gate", json={"scan_id": scan["id"], "min_score": 100})
        assert resp.status_code == 200
        assert resp.json()["passed"] is False

    def test_gate_unknown_scan_returns_404(self, db_client: TestClient):
        """Gate on a nonexistent scan_id returns 404."""
        resp = db_client.post(
            "/gate",
            json={"scan_id": "00000000-0000-0000-0000-000000000099", "min_score": 70},
        )
        assert resp.status_code == 404

    def test_audit_log_coverage_all_routes(self, test_db_dsn: str):
        """All 5 routes write at least one audit_log row each."""
        import psycopg2  # type: ignore[import-untyped]

        os.environ["DATABASE_URL"] = test_db_dsn
        try:
            app = create_app()
            client = TestClient(app, raise_server_exceptions=True)

            # POST /scans
            scan = _scan_with_client(client, _KNOWN_BAD)
            scan_id = scan["id"]

            # GET /scans/{id}
            resp = client.get(f"/scans/{scan_id}")
            assert resp.status_code == 200

            # GET /scans/{id}/report
            resp = client.get(f"/scans/{scan_id}/report?fmt=json")
            assert resp.status_code == 200

            # GET /scans/{id}/aibom
            resp = client.get(f"/scans/{scan_id}/aibom")
            assert resp.status_code == 200

            # POST /gate
            resp = client.post("/gate", json={"scan_id": scan_id, "min_score": 0})
            assert resp.status_code == 200
        finally:
            os.environ.pop("DATABASE_URL", None)

        conn = psycopg2.connect(test_db_dsn)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT action FROM audit_log ORDER BY ts")
                actions = [row[0] for row in cur.fetchall()]
        finally:
            conn.close()

        # Check each route category is represented
        assert any(a == "POST /scans" for a in actions), (
            "POST /scans not found in audit_log"
        )
        assert any(a.startswith(f"GET /scans/{scan_id}") for a in actions), (
            f"GET /scans/{scan_id}[...] not found in audit_log"
        )
        assert any(a == "POST /gate" for a in actions), (
            "POST /gate not found in audit_log"
        )
        # Verify at least 5 rows were written (one per route call)
        assert len(actions) >= 5, (
            f"Expected >=5 audit_log rows across all routes; got {len(actions)}"
        )
