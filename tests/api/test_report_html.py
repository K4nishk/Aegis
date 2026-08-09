"""tests/api/test_report_html.py — HTML report tests (KCH-14).

Unit tests (no DB): exercise render_html_report + build_report_context directly.
Integration tests (require local Postgres): exercise GET /scans/{scan_id}/report?fmt=html
  via the FastAPI TestClient with a real scan persisted first.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.report_html import (
    _OWASP_REF,
    _RULE_SEVERITY,
    build_report_context,
    render_html_report,
)

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "mcp"
_KNOWN_BAD = _FIXTURES / "known_bad.json"
_CLAUDE_DESKTOP = _FIXTURES / "claude_desktop.json"

# ---------------------------------------------------------------------------
# Unit tests — no DB required
# ---------------------------------------------------------------------------


class TestOwaspMapping:
    """All posture rules have an OWASP ref and a severity level."""

    _ALL_RULES = ["trifecta_path", "poisoning", "rug_pull", "secret_in_desc", "no_auth", "no_ratelimit"]

    def test_all_rules_have_owasp_ref(self):
        for rule in self._ALL_RULES:
            assert rule in _OWASP_REF, f"Missing OWASP ref for rule: {rule}"

    def test_owasp_ref_format(self):
        for rule, (ref, title) in _OWASP_REF.items():
            assert ref.startswith("LLM"), f"Expected LLM ref, got {ref!r} for {rule}"
            assert title, f"Empty OWASP title for {rule}"

    def test_all_rules_have_severity(self):
        for rule in self._ALL_RULES:
            assert rule in _RULE_SEVERITY

    def test_trifecta_path_is_critical(self):
        assert _RULE_SEVERITY["trifecta_path"] == "CRITICAL"

    def test_no_ratelimit_is_low(self):
        assert _RULE_SEVERITY["no_ratelimit"] == "LOW"


class TestBuildReportContext:
    """build_report_context produces correct context dict."""

    def _meta(self, score: int = 85, triggered: list | None = None) -> dict:
        return {
            "score": score,
            "triggered_rules": triggered or [],
            "trifecta_findings": [],
            "warnings": [],
            "rules": [
                {"rule": "trifecta_path", "triggered": False, "deduction": 0, "evidence": []},
                {"rule": "poisoning", "triggered": False, "deduction": 0, "evidence": []},
                {"rule": "rug_pull", "triggered": False, "deduction": 0, "evidence": []},
                {"rule": "secret_in_desc", "triggered": False, "deduction": 0, "evidence": []},
                {"rule": "no_auth", "triggered": True, "deduction": 10, "evidence": ["no auth"]},
                {"rule": "no_ratelimit", "triggered": True, "deduction": 5, "evidence": ["no rl"]},
            ],
            "trifecta_profiles": {"server::tool1": {}, "server::tool2": {}},
        }

    def test_score_passed_through(self):
        ctx = build_report_context(scan_id="abc-123", meta=self._meta(score=72))
        assert ctx["score"] == 72

    def test_score_class_good(self):
        ctx = build_report_context(scan_id="abc", meta=self._meta(score=85))
        assert ctx["score_class"] == "good"

    def test_score_class_critical(self):
        ctx = build_report_context(scan_id="abc", meta=self._meta(score=30))
        assert ctx["score_class"] == "critical"

    def test_findings_only_triggered(self):
        ctx = build_report_context(scan_id="abc", meta=self._meta())
        rules_in_findings = {f["rule"] for f in ctx["findings"]}
        assert "no_auth" in rules_in_findings
        assert "no_ratelimit" in rules_in_findings
        # non-triggered rules should NOT appear in findings list
        assert "trifecta_path" not in rules_in_findings

    def test_findings_ranked_severity(self):
        """MEDIUM (no_auth) comes before LOW (no_ratelimit)."""
        ctx = build_report_context(scan_id="abc", meta=self._meta())
        findings = ctx["findings"]
        severities = [f["severity"] for f in findings]
        # no_auth=MEDIUM should appear before no_ratelimit=LOW
        assert severities.index("MEDIUM") < severities.index("LOW")

    def test_owasp_ref_present_in_findings(self):
        ctx = build_report_context(scan_id="abc", meta=self._meta())
        for f in ctx["findings"]:
            assert f["owasp_ref"], f"Missing owasp_ref in finding: {f}"

    def test_component_count_from_profiles(self):
        ctx = build_report_context(scan_id="abc", meta=self._meta())
        assert ctx["component_count"] == 2

    def test_aibom_url_passed_through(self):
        ctx = build_report_context(scan_id="abc", meta=self._meta(), aibom_url="http://x/aibom")
        assert ctx["aibom_url"] == "http://x/aibom"


class TestRenderHtmlReport:
    """render_html_report returns valid HTML with required content."""

    def _make_context(self, score: int = 55) -> dict:
        meta = {
            "score": score,
            "triggered_rules": ["trifecta_path"],
            "trifecta_findings": [
                {"path": ["server::reader", "server::browser", "server::sender"], "confidence": "high"}
            ],
            "warnings": [],
            "rules": [
                {
                    "rule": "trifecta_path",
                    "triggered": True,
                    "deduction": 40,
                    "evidence": ["path: reader → browser → sender"],
                },
            ],
            "trifecta_profiles": {"server::reader": {}},
        }
        return build_report_context(scan_id="test-scan-1234", meta=meta, label="unit-test")

    def test_returns_html_string(self):
        html = render_html_report(self._make_context())
        assert isinstance(html, str)
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_contains_scan_id(self):
        html = render_html_report(self._make_context())
        assert "test-scan-1234" in html

    def test_contains_score(self):
        html = render_html_report(self._make_context(score=55))
        assert "55" in html

    def test_contains_prototype_banner(self):
        html = render_html_report(self._make_context())
        assert "PROTOTYPE" in html or "Proof-of-Concept" in html or "PoV" in html

    def test_contains_owasp_ref(self):
        html = render_html_report(self._make_context())
        assert "LLM01" in html

    def test_contains_trifecta_path(self):
        html = render_html_report(self._make_context())
        assert "reader" in html
        assert "browser" in html
        assert "sender" in html

    def test_contains_aibom_section(self):
        html = render_html_report(self._make_context())
        assert "aibom" in html.lower() or "AI Bill" in html or "AI-BOM" in html

    def test_html_escaping(self):
        """XSS: malicious label should be escaped in output."""
        meta = {
            "score": 80,
            "triggered_rules": [],
            "trifecta_findings": [],
            "warnings": [],
            "rules": [],
            "trifecta_profiles": {},
        }
        ctx = build_report_context(
            scan_id="xss-test",
            meta=meta,
            label='<script>alert("xss")</script>',
        )
        html = render_html_report(ctx)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# No-DB API tests — exercise the endpoint via TestClient
# ---------------------------------------------------------------------------


class TestReportHtmlEndpointNoDB:
    """GET /scans/{scan_id}/report?fmt=html works in ephemeral (no-DB) mode.

    We POST /scans to get a scan_id, then verify the report endpoint.
    Without a DB, GET /scans/{scan_id}/report returns 503 (DB required).
    So instead we test the rendering pipeline directly + check the route
    rejects invalid fmt values.
    """

    def setup_method(self):
        os.environ.pop("DATABASE_URL", None)

    def test_invalid_fmt_returns_422(self):
        app = create_app()
        client = TestClient(app)
        # Need a plausible scan_id — endpoint validates fmt before hitting DB
        resp = client.get(
            "/scans/00000000-0000-0000-0000-000000000001/report?fmt=xml",
            headers={"X-API-Key": "test"},
        )
        assert resp.status_code == 422

    def test_html_fmt_accepted_in_schema(self):
        """fmt=html passes validation (503 expected without DB, not 422)."""
        app = create_app()
        client = TestClient(app)
        resp = client.get(
            "/scans/00000000-0000-0000-0000-000000000001/report?fmt=html",
            headers={"X-API-Key": "test"},
        )
        # 503 = no DB, not 422 (which would mean fmt=html is rejected)
        assert resp.status_code == 503

    def test_download_param_accepted(self):
        """download=true passes validation (503 expected without DB)."""
        app = create_app()
        client = TestClient(app)
        resp = client.get(
            "/scans/00000000-0000-0000-0000-000000000001/report?fmt=html&download=true",
            headers={"X-API-Key": "test"},
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Integration tests — require local Postgres
# ---------------------------------------------------------------------------


class TestReportHtmlIntegration:
    """End-to-end: POST /scans → GET /scans/{id}/report?fmt=html."""

    @pytest.fixture
    def db_client(self, test_db_dsn: str) -> TestClient:
        os.environ["DATABASE_URL"] = test_db_dsn
        app = create_app()
        client = TestClient(app)
        yield client
        os.environ.pop("DATABASE_URL", None)

    def test_html_report_200(self, db_client: TestClient):
        """Known-bad scan produces a 200 HTML report."""
        mcp_json = json.loads(_KNOWN_BAD.read_text())
        scan_resp = db_client.post("/scans", json={"mcp_json": mcp_json, "label": "html-test"})
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        resp = db_client.get(f"/scans/{scan_id}/report?fmt=html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_html_report_contains_score(self, db_client: TestClient):
        mcp_json = json.loads(_KNOWN_BAD.read_text())
        scan_resp = db_client.post("/scans", json={"mcp_json": mcp_json})
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]
        expected_score = scan_resp.json()["score"]

        html = db_client.get(f"/scans/{scan_id}/report?fmt=html").text
        assert str(expected_score) in html

    def test_html_report_contains_prototype_banner(self, db_client: TestClient):
        mcp_json = json.loads(_CLAUDE_DESKTOP.read_text())
        scan_resp = db_client.post("/scans", json={"mcp_json": mcp_json})
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        html = db_client.get(f"/scans/{scan_id}/report?fmt=html").text
        assert "PROTOTYPE" in html or "Proof-of-Concept" in html

    def test_html_report_contains_owasp_refs(self, db_client: TestClient):
        mcp_json = json.loads(_KNOWN_BAD.read_text())
        scan_resp = db_client.post("/scans", json={"mcp_json": mcp_json})
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        html = db_client.get(f"/scans/{scan_id}/report?fmt=html").text
        # known_bad triggers trifecta_path → LLM01
        assert "LLM01" in html

    def test_html_download_adds_content_disposition(self, db_client: TestClient):
        mcp_json = json.loads(_KNOWN_BAD.read_text())
        scan_resp = db_client.post("/scans", json={"mcp_json": mcp_json})
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        resp = db_client.get(f"/scans/{scan_id}/report?fmt=html&download=true")
        assert resp.status_code == 200
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert ".html" in cd

    def test_html_report_404_unknown_scan(self, db_client: TestClient):
        resp = db_client.get(
            "/scans/00000000-0000-0000-0000-000000000099/report?fmt=html"
        )
        assert resp.status_code == 404

    def test_html_report_aibom_link_present(self, db_client: TestClient):
        mcp_json = json.loads(_KNOWN_BAD.read_text())
        scan_resp = db_client.post("/scans", json={"mcp_json": mcp_json})
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        html = db_client.get(f"/scans/{scan_id}/report?fmt=html").text
        assert "aibom" in html.lower()
