"""api/report_html.py — Jinja2 HTML report rendering for KCH-14.

Converts stored scan metadata into a rich HTML report with:
  - Posture score badge + label
  - Findings ranked by (severity, blast_radius)
  - OWASP LLM Top 10 (2025) references
  - Trifecta attack-path listing
  - Link to AI-BOM
  - Prototype/PoV banner (in template)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

# ---------------------------------------------------------------------------
# OWASP mapping
# ---------------------------------------------------------------------------

# OWASP LLM Top 10 2025 references for each Aegis posture rule.
_OWASP_REF: dict[str, tuple[str, str]] = {
    "trifecta_path": ("LLM01:2025", "Prompt Injection"),
    "poisoning": ("LLM01:2025", "Prompt Injection"),
    "rug_pull": ("LLM03:2025", "Supply Chain"),
    "secret_in_desc": ("LLM02:2025", "Sensitive Information Disclosure"),
    "no_auth": ("LLM06:2025", "Excessive Agency"),
    "no_ratelimit": ("LLM10:2025", "Unbounded Consumption"),
}

# Severity derived from rule deduction weight.
_RULE_SEVERITY: dict[str, str] = {
    "trifecta_path": "CRITICAL",
    "poisoning": "HIGH",
    "rug_pull": "HIGH",
    "secret_in_desc": "MEDIUM",
    "no_auth": "MEDIUM",
    "no_ratelimit": "LOW",
}

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "OK": 4,
}

# ---------------------------------------------------------------------------
# Data model for template context
# ---------------------------------------------------------------------------


@dataclass
class FindingRow:
    rule: str
    severity: str
    owasp_ref: str
    owasp_title: str
    deduction: int
    evidence: list[str]
    triggered: bool


# ---------------------------------------------------------------------------
# Jinja2 environment (singleton)
# ---------------------------------------------------------------------------

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env: Environment | None = None


def _get_env() -> Environment:
    global _env  # noqa: PLW0603
    if _env is None:
        _env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
    return _env


# ---------------------------------------------------------------------------
# Score helpers
# ---------------------------------------------------------------------------


def _score_class(score: int) -> str:
    if score < 40:
        return "critical"
    if score < 60:
        return "high"
    if score < 80:
        return "medium"
    return "good"


def _score_label(score: int) -> str:
    if score < 40:
        return "Critical risk — immediate remediation required"
    if score < 60:
        return "High risk — significant security gaps detected"
    if score < 80:
        return "Medium risk — some controls missing"
    return "Low risk — posture looks healthy"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_report_context(
    *,
    scan_id: str,
    meta: dict[str, Any],
    label: str | None = None,
    created_at: str | None = None,
    completed_at: str | None = None,
    component_count: int = 0,
    aibom_url: str | None = None,
) -> dict[str, Any]:
    """Build the Jinja2 template context dict from stored scan metadata."""
    score: int = meta.get("score", 0)
    triggered_rules: list[str] = meta.get("triggered_rules", [])
    trifecta_findings: list[dict[str, Any]] = meta.get("trifecta_findings", [])
    warnings: list[str] = meta.get("warnings", [])
    raw_rules: list[dict[str, Any]] = meta.get("rules", [])

    # Build finding rows for triggered rules only (not OK rules — those are noise).
    rows: list[FindingRow] = []
    for r in raw_rules:
        rule_name: str = r["rule"]
        triggered: bool = r.get("triggered", False)
        deduction: int = r.get("deduction", 0)
        evidence: list[str] = r.get("evidence", [])
        owasp_ref, owasp_title = _OWASP_REF.get(rule_name, ("—", ""))
        severity = _RULE_SEVERITY.get(rule_name, "LOW") if triggered else "OK"
        rows.append(
            FindingRow(
                rule=rule_name,
                severity=severity,
                owasp_ref=owasp_ref,
                owasp_title=owasp_title,
                deduction=deduction,
                evidence=evidence,
                triggered=triggered,
            )
        )

    # Rank: triggered first (by severity), then OK rules at end.
    rows.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), not f.triggered))

    # Only show triggered findings prominently; include OK rows too for completeness.
    return {
        "scan_id": scan_id,
        "label": label,
        "score": score,
        "score_class": _score_class(score),
        "score_label": _score_label(score),
        "triggered_rules": triggered_rules,
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity,
                "owasp_ref": f.owasp_ref,
                "owasp_title": f.owasp_title,
                "deduction": f.deduction,
                "evidence": f.evidence,
                "triggered": f.triggered,
            }
            for f in rows
            if f.triggered  # only triggered rules in the findings table
        ],
        "trifecta_findings": trifecta_findings,
        "warnings": warnings,
        "created_at": created_at,
        "completed_at": completed_at,
        "component_count": component_count,
        "aibom_url": aibom_url,
    }


def render_html_report(context: dict[str, Any]) -> str:
    """Render the HTML report template with *context*. Returns HTML string."""
    tpl = _get_env().get_template("report.html")
    return tpl.render(**context)
