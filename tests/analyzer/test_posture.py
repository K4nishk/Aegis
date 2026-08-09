"""
tests/analyzer/test_posture.py

Golden + unit tests for analyzer.posture — deterministic posture score rubric.

Rubric (ARD §14):
  100 start
  −40 trifecta_path
  −15 poisoning
  −15 rug_pull
  −10 secret_in_desc
  −10 no_auth
  −5  no_ratelimit
  floor 0

AC:
  • same input → same score (golden tests verify this)
  • no safe<dangerous inversion (RA-3): a safer config always scores ≥ a riskier one

Ref: ARD §14, §9 / KCH-10
"""

from __future__ import annotations

from analyzer.posture import (
    MAX_SCORE,
    RULES,
    PostureScore,
    score_posture,
)
from analyzer.trifecta import analyze_trifecta
from parser.mcp import parse_mcp_config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg(tools: list[dict], server: str = "srv") -> dict:
    """Wrap a list of tool dicts in a minimal mcp config."""
    return {"mcpServers": {server: {"tools": tools}}}


def _score(tools: list[dict], server: str = "srv") -> PostureScore:
    pr = parse_mcp_config(_cfg(tools, server))
    return score_posture(pr)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


def test_max_score_is_100() -> None:
    assert MAX_SCORE == 100


def test_rules_catalogue_complete() -> None:
    expected = {
        "trifecta_path",
        "poisoning",
        "rug_pull",
        "secret_in_desc",
        "no_auth",
        "no_ratelimit",
    }
    assert set(RULES.keys()) == expected


def test_rules_deduction_values() -> None:
    assert RULES["trifecta_path"] == 40
    assert RULES["poisoning"] == 15
    assert RULES["rug_pull"] == 15
    assert RULES["secret_in_desc"] == 10
    assert RULES["no_auth"] == 10
    assert RULES["no_ratelimit"] == 5


# ---------------------------------------------------------------------------
# Golden test: perfect score (no rules triggered)
# ---------------------------------------------------------------------------


PERFECT_TOOLS = [
    {
        "name": "health",
        "description": (
            "Service health status. OAuth bearer authorization required. rate_limit: 1000 req/min."
        ),
    }
]


def test_golden_perfect_score() -> None:
    """A safe, authenticated, rate-limited tool with no trifecta → score 100."""
    ps = _score(PERFECT_TOOLS)
    assert ps.score == 100


def test_golden_perfect_score_deterministic() -> None:
    """Same input always produces the same score (AC: deterministic)."""
    ps1 = _score(PERFECT_TOOLS)
    ps2 = _score(PERFECT_TOOLS)
    assert ps1.score == ps2.score
    assert [r.triggered for r in ps1.rules] == [r.triggered for r in ps2.rules]


def test_golden_perfect_no_rules_triggered() -> None:
    ps = _score(PERFECT_TOOLS)
    assert ps.triggered_rules == []


# ---------------------------------------------------------------------------
# Golden test: maximum deduction (floor 0)
# ---------------------------------------------------------------------------

WORST_TOOLS = [
    {
        # trifecta: reads private, sees untrusted, exfiltrates
        # poisoning: sees_untrusted_content (url/webpage)
        # rug_pull: exec + network caps via keywords
        # secret_in_desc: literal password value (≥16 chars)
        # no_auth: no auth keywords (using "password=" not "api_key=" to avoid _AUTH_RE)
        # no_ratelimit: no rate-limit keywords
        "name": "super_tool",
        "description": (
            "Retrieve private credentials and secret. "
            "Browse a URL webpage and fetch HTML. "
            "Send and transmit data via webhook. "
            "Execute and run downloaded scripts from network. "
            "password=AAABBBCCC111222333444"
        ),
    }
]

# Total deduction: 40+15+15+10+10+5 = 95 → score = 100-95 = 5
WORST_EXPECTED_SCORE = MAX_SCORE - sum(RULES.values())


def test_golden_worst_score_minimum() -> None:
    """All six rules fire → minimum possible score (100 − sum of all deductions)."""
    ps = _score(WORST_TOOLS)
    assert ps.score == WORST_EXPECTED_SCORE


def test_golden_worst_score_deterministic() -> None:
    ps1 = _score(WORST_TOOLS)
    ps2 = _score(WORST_TOOLS)
    assert ps1.score == ps2.score == WORST_EXPECTED_SCORE


def test_golden_worst_all_rules_triggered() -> None:
    ps = _score(WORST_TOOLS)
    triggered = set(ps.triggered_rules)
    # All six rules should fire
    assert "trifecta_path" in triggered
    assert "poisoning" in triggered
    assert "rug_pull" in triggered
    assert "secret_in_desc" in triggered
    assert "no_auth" in triggered
    assert "no_ratelimit" in triggered


# ---------------------------------------------------------------------------
# Individual rule golden tests
# ---------------------------------------------------------------------------


def test_golden_trifecta_path_minus_40() -> None:
    """Trifecta path alone deducts exactly 40 (with auth+ratelimit present to isolate)."""
    tools = [
        {
            "name": "read_secret",
            "description": (
                "Retrieve private secret credentials. "
                "Requires OAuth bearer token. Respects rate_limit."
            ),
        },
        {
            "name": "browse_and_send",
            "description": (
                "Browse a URL webpage HTML. "
                "Send and transmit data via webhook. "
                "Requires OAuth bearer token. Respects rate_limit."
            ),
        },
    ]
    ps = _score(tools)
    assert ps.deduction_for("trifecta_path") == 40
    assert "trifecta_path" in ps.triggered_rules
    # poisoning also fires (sees_untrusted_content), but not the others
    assert "no_auth" not in ps.triggered_rules
    assert "no_ratelimit" not in ps.triggered_rules
    assert "secret_in_desc" not in ps.triggered_rules


def test_golden_poisoning_minus_15() -> None:
    """Tool that fetches a URL → suc=True (poisoning −15), no trifecta.

    Uses a URL-fetch tool: suc=True via direct inbound-content indicator, but
    no rpd or exf signal → not all 3 trifecta caps risk-present.
    """
    # "validate_input" explicitly processes untrusted data (suc=True via direct
    # keyword) but has no read/network/exec caps → rpd=False, exf=False → no
    # trifecta path; only the poisoning rule fires.
    tools = [
        {
            "name": "validate_input",
            "description": (
                "Sanitise and validate untrusted user data before processing. "
                "OAuth bearer required. rate_limit enforced."
            ),
        }
    ]
    ps = _score(tools)
    assert ps.deduction_for("poisoning") == 15
    assert "poisoning" in ps.triggered_rules
    # No trifecta: exf=False → not all 3 caps risk-present
    assert "trifecta_path" not in ps.triggered_rules


def test_golden_rug_pull_exec_network_minus_15() -> None:
    """exec + network caps → rug_pull −15 (with auth+rl to isolate)."""
    tools = [
        {
            "name": "run_remote",
            "description": (
                "Execute an HTTP request and run the returned script. "
                "Uses OAuth bearer token. Respects rate_limit."
            ),
        }
    ]
    ps = _score(tools)
    assert ps.deduction_for("rug_pull") == 15
    assert "rug_pull" in ps.triggered_rules


def test_golden_rug_pull_exec_kw_minus_15() -> None:
    """exec cap + install keyword → rug_pull −15."""
    tools = [
        {
            "name": "install_plugin",
            "description": (
                "Execute and install a plugin extension. "
                "Uses OAuth bearer token. Respects rate_limit."
            ),
        }
    ]
    ps = _score(tools)
    assert ps.deduction_for("rug_pull") == 15
    assert "rug_pull" in ps.triggered_rules


def test_golden_secret_in_desc_minus_10() -> None:
    """Literal secret in description → −10 (with auth+rl present)."""
    tools = [
        {
            "name": "safe_tool",
            "description": (
                "List queue items. "
                "token=SECRETVALUE12345678 "
                "Uses OAuth bearer for authorization. Respects rate_limit."
            ),
        }
    ]
    ps = _score(tools)
    assert ps.deduction_for("secret_in_desc") == 10
    assert "secret_in_desc" in ps.triggered_rules


def test_golden_no_auth_minus_10() -> None:
    """No auth keywords → −10 (with rl present, no other risk)."""
    tools = [
        {
            "name": "list_items",
            "description": "List all items in the queue. Respects rate_limit of 100 req/min.",
        }
    ]
    ps = _score(tools)
    assert ps.deduction_for("no_auth") == 10
    assert "no_auth" in ps.triggered_rules
    assert "no_ratelimit" not in ps.triggered_rules


def test_golden_no_ratelimit_minus_5() -> None:
    """No rate-limit keywords → −5 (with auth present, no other risk)."""
    tools = [
        {
            "name": "list_items",
            "description": "List all items. Requires OAuth bearer token for authorization.",
        }
    ]
    ps = _score(tools)
    assert ps.deduction_for("no_ratelimit") == 5
    assert "no_ratelimit" in ps.triggered_rules
    assert "no_auth" not in ps.triggered_rules


# ---------------------------------------------------------------------------
# RA-3: no safe<dangerous inversion
# ---------------------------------------------------------------------------


def test_ra3_safer_scores_higher_than_riskier() -> None:
    """A tool with auth+ratelimit always scores ≥ same tool without them."""
    safe_tools = [
        {
            "name": "list_items",
            "description": ("List items. Requires OAuth bearer token. Respects rate_limit."),
        }
    ]
    risky_tools = [
        {
            "name": "list_items",
            "description": "List items.",
        }
    ]
    safe_score = _score(safe_tools).score
    risky_score = _score(risky_tools).score
    assert safe_score >= risky_score, (
        f"Safe config scored {safe_score} < risky config {risky_score} — RA-3 violation"
    )


def test_ra3_adding_trifecta_lowers_score() -> None:
    """Adding a trifecta to a graph always lowers (or keeps equal) the score."""
    base_tools = [
        {
            "name": "list_queue",
            "description": "List queue items. OAuth bearer. rate_limit enforced.",
        }
    ]
    trifecta_tools = base_tools + [
        {
            "name": "read_and_exfil",
            "description": (
                "Get private secret credentials, browse URL webpage, "
                "send data via webhook. OAuth bearer. rate_limit enforced."
            ),
        }
    ]
    base_score = _score(base_tools).score
    trifecta_score = _score(trifecta_tools).score
    assert trifecta_score <= base_score, (
        f"Trifecta config scored {trifecta_score} > base {base_score} — RA-3 violation"
    )


def test_ra3_secret_in_desc_lowers_score() -> None:
    """Adding a literal secret to description always lowers score."""
    clean_tools = [
        {
            "name": "api_tool",
            "description": "Call the API. OAuth bearer. rate_limit enforced.",
        }
    ]
    secret_tools = [
        {
            "name": "api_tool",
            "description": (
                "Call the API. api_key=ABCDEF1234567890 OAuth bearer. rate_limit enforced."
            ),
        }
    ]
    clean_score = _score(clean_tools).score
    secret_score = _score(secret_tools).score
    assert secret_score <= clean_score


def test_ra3_rug_pull_lowers_score() -> None:
    """Adding exec+network to a tool always lowers score."""
    safe_tools = [
        {
            "name": "list",
            "description": "List items. OAuth bearer. rate_limit enforced.",
        }
    ]
    risky_tools = [
        {
            "name": "run_remote",
            "description": (
                "Execute an HTTP request and run the returned script. "
                "OAuth bearer. rate_limit enforced."
            ),
        }
    ]
    assert _score(risky_tools).score <= _score(safe_tools).score


# ---------------------------------------------------------------------------
# PostureScore properties
# ---------------------------------------------------------------------------


def test_posture_score_triggered_rules_property() -> None:
    ps = _score(WORST_TOOLS)
    assert isinstance(ps.triggered_rules, list)
    assert all(isinstance(r, str) for r in ps.triggered_rules)


def test_posture_score_deduction_for_missing_rule_is_zero() -> None:
    ps = _score(PERFECT_TOOLS)
    assert ps.deduction_for("nonexistent_rule") == 0


def test_posture_score_rules_order() -> None:
    """Rules appear in rubric order."""
    ps = _score(WORST_TOOLS)
    names = [r.rule for r in ps.rules]
    assert names == [
        "trifecta_path",
        "poisoning",
        "rug_pull",
        "secret_in_desc",
        "no_auth",
        "no_ratelimit",
    ]


def test_posture_score_all_rules_present() -> None:
    ps = _score(PERFECT_TOOLS)
    assert len(ps.rules) == len(RULES)


def test_rule_result_has_evidence() -> None:
    ps = _score(WORST_TOOLS)
    for rule in ps.rules:
        assert isinstance(rule.evidence, list)


def test_not_triggered_rule_has_zero_deduction() -> None:
    ps = _score(PERFECT_TOOLS)
    for rule in ps.rules:
        assert not rule.triggered
        assert rule.deduction == 0


# ---------------------------------------------------------------------------
# Pre-computed trifecta_result accepted
# ---------------------------------------------------------------------------


def test_score_posture_accepts_precomputed_trifecta() -> None:
    """Passing trifecta_result produces the same score as computing it internally."""
    pr = parse_mcp_config(_cfg(WORST_TOOLS))
    tr = analyze_trifecta(pr)
    ps_with = score_posture(pr, tr)
    ps_without = score_posture(pr)
    assert ps_with.score == ps_without.score
    assert [r.triggered for r in ps_with.rules] == [r.triggered for r in ps_without.rules]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_config_scores_below_100() -> None:
    """Empty config: no tools → no_auth and no_ratelimit fire → 100−10−5 = 85."""
    pr = parse_mcp_config({"mcpServers": {}})
    ps = score_posture(pr)
    # no tools: no_auth (−10) + no_ratelimit (−5) = 85
    assert ps.score == 85
    assert "no_auth" in ps.triggered_rules
    assert "no_ratelimit" in ps.triggered_rules


def test_score_floor_is_zero() -> None:
    """Score never goes below 0 even with pathological input."""
    # Theoretical max deduction: 40+15+15+10+10+5 = 95. Score = max(0, 100-95) = 5.
    # But if we add more risk: still can't go below 0.
    ps = _score(WORST_TOOLS)
    assert ps.score >= 0


def test_single_tool_all_safe_keywords() -> None:
    """Tool with all safety markers and no risky caps: perfect score."""
    tools = [
        {
            "name": "health",
            "description": (
                "Service health status. OAuth bearer required. rate_limit: 60 req/min."
            ),
        }
    ]
    ps = _score(tools)
    assert ps.score == 100
