"""
analyzer/posture.py — Deterministic posture score rubric 0–100 (KCH-10).

Rubric (ARD §14):
  Start:         100
  −40  trifecta_path       trifecta attack path detected (reads_private_data →
                           sees_untrusted_content → can_exfiltrate)
  −15  poisoning           any tool sees_untrusted_content risk-present
                           (prompt-injection vector)
  −15  rug_pull            any tool can dynamically pull and execute external code
                           (exec + network caps, or install/update + exec keywords)
  −10  secret_in_desc      literal secret value embedded in a tool description
  −10  no_auth             no tool exposes authentication evidence
  −5   no_ratelimit        no tool exposes rate-limit evidence
  Floor: 0

Same input always produces the same score (deterministic, no randomness).

Ref: ARD §14, §9 / KCH-10
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from analyzer.trifecta import TrifectaResult, analyze_trifecta
from parser.mcp import ParseResult, ToolNode

# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------

RULES: dict[str, int] = {
    "trifecta_path": 40,
    "poisoning": 15,
    "rug_pull": 15,
    "secret_in_desc": 10,
    "no_auth": 10,
    "no_ratelimit": 5,
}

MAX_SCORE: int = 100

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Literal secret value after a secret keyword: keyword = "value" or keyword: value
# Value must be ≥16 chars of base64/hex/alphanumeric (likely a real secret, not a word).
_SECRET_IN_DESC_RE = re.compile(
    r"(?:password|passwd|secret|api[_\-.]?key|token|credential|auth)[=:\s]+['\"]?[A-Za-z0-9+/\-_]{16,}['\"]?",
    re.I,
)

# Authentication-related keywords: evidence the server enforces authn/authz.
_AUTH_RE = re.compile(
    r"\b(oauth|bearer|authorization|auth[_\-.]?token|authenticate|hmac|jwt|saml|"
    r"tls|mtls|api[_\-.]?key|signed[_\-.]?request|x-api-key)\b",
    re.I,
)

# Rate-limit / throttle keywords.
_RATELIMIT_RE = re.compile(
    r"\b(rate[_\-.]?limit|throttle|backoff|retry.after|quota|burst.limit)\b",
    re.I,
)

# Rug-pull keywords: install/download external code at runtime.
_RUG_PULL_KW_RE = re.compile(
    r"\b(install|download|pull|update|upgrade|plugin|extension|package|module|script)\b",
    re.I,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class RuleResult:
    """Outcome of evaluating one scoring rule."""

    rule: str
    deduction: int  # actual points removed (0 when not triggered)
    triggered: bool
    evidence: list[str] = field(default_factory=list)


@dataclass
class PostureScore:
    """Deterministic posture score for one parsed tool graph.

    Attributes:
        score:    Final clamped score in [0, 100].
        rules:    One :class:`RuleResult` per rule, in rubric order.
    """

    score: int
    rules: list[RuleResult]

    @property
    def triggered_rules(self) -> list[str]:
        """Names of rules that fired (deducted points)."""
        return [r.rule for r in self.rules if r.triggered]

    def deduction_for(self, rule: str) -> int:
        """Convenience: deduction amount for a named rule (0 if not triggered)."""
        for r in self.rules:
            if r.rule == rule:
                return r.deduction
        return 0


# ---------------------------------------------------------------------------
# Rule evaluators
# ---------------------------------------------------------------------------


def _tool_full_text(node: ToolNode) -> str:
    """Concatenate all user-visible text for a node."""
    import json

    schema = node.raw_def.get("inputSchema") or node.raw_def.get("input_schema") or {}
    return " ".join(
        filter(
            None,
            [
                node.tool_name,
                str(node.raw_def.get("description", "")),
                json.dumps(schema),
            ],
        )
    )


def _eval_trifecta_path(trifecta: TrifectaResult) -> RuleResult:
    triggered = len(trifecta.findings) > 0
    evidence = [f"path: {' → '.join(f.path)}" for f in trifecta.findings[:3]]
    return RuleResult(
        rule="trifecta_path",
        deduction=RULES["trifecta_path"] if triggered else 0,
        triggered=triggered,
        evidence=evidence,
    )


def _eval_poisoning(trifecta: TrifectaResult) -> RuleResult:
    """Any tool with sees_untrusted_content risk-present is a poisoning vector."""
    risky: list[str] = [
        key
        for key, profile in trifecta.profiles.items()
        if profile.sees_untrusted_content.is_risk_present()
    ]
    triggered = len(risky) > 0
    evidence = [f"sees_untrusted_content risk on: {k}" for k in risky[:5]]
    return RuleResult(
        rule="poisoning",
        deduction=RULES["poisoning"] if triggered else 0,
        triggered=triggered,
        evidence=evidence,
    )


def _eval_rug_pull(nodes: list[ToolNode]) -> RuleResult:
    """Rug-pull: tool can pull and execute external code at runtime.

    Triggered when any node:
      (a) has both 'exec' AND 'network' capabilities, OR
      (b) description matches rug-pull keywords AND has 'exec' cap.
    """
    evidence: list[str] = []
    for node in nodes:
        caps = set(node.caps)
        if "exec" in caps and "network" in caps:
            evidence.append(
                f"{node.node_key}: exec+network caps (can download and run external code)"
            )
        elif "exec" in caps and _RUG_PULL_KW_RE.search(_tool_full_text(node)):
            evidence.append(f"{node.node_key}: exec cap + install/update keywords")
    triggered = len(evidence) > 0
    return RuleResult(
        rule="rug_pull",
        deduction=RULES["rug_pull"] if triggered else 0,
        triggered=triggered,
        evidence=evidence[:5],
    )


def _eval_secret_in_desc(nodes: list[ToolNode]) -> RuleResult:
    """Detect literal secret values embedded in tool descriptions."""
    evidence: list[str] = []
    for node in nodes:
        desc = str(node.raw_def.get("description", ""))
        match = _SECRET_IN_DESC_RE.search(desc)
        if match:
            # Redact: show only the keyword portion, not the secret value.
            snippet = desc[max(0, match.start() - 10) : match.start() + 30]
            evidence.append(f"{node.node_key}: '{snippet}…'")
    triggered = len(evidence) > 0
    return RuleResult(
        rule="secret_in_desc",
        deduction=RULES["secret_in_desc"] if triggered else 0,
        triggered=triggered,
        evidence=evidence[:5],
    )


def _eval_no_auth(nodes: list[ToolNode]) -> RuleResult:
    """No-auth: no tool in the graph exposes authentication evidence."""
    auth_nodes: list[str] = []
    for node in nodes:
        if _AUTH_RE.search(_tool_full_text(node)):
            auth_nodes.append(node.node_key)
    # Rule fires when there is NO auth evidence.
    triggered = len(auth_nodes) == 0
    evidence: list[str]
    if triggered:
        evidence = ["no authentication keywords found across all tools"]
    else:
        evidence = [f"auth evidence in: {', '.join(auth_nodes[:5])}"]
    return RuleResult(
        rule="no_auth",
        deduction=RULES["no_auth"] if triggered else 0,
        triggered=triggered,
        evidence=evidence,
    )


def _eval_no_ratelimit(nodes: list[ToolNode]) -> RuleResult:
    """No-ratelimit: no tool mentions rate-limiting / throttling."""
    rl_nodes: list[str] = []
    for node in nodes:
        if _RATELIMIT_RE.search(_tool_full_text(node)):
            rl_nodes.append(node.node_key)
    triggered = len(rl_nodes) == 0
    evidence: list[str]
    if triggered:
        evidence = ["no rate-limit keywords found across all tools"]
    else:
        evidence = [f"rate-limit evidence in: {', '.join(rl_nodes[:5])}"]
    return RuleResult(
        rule="no_ratelimit",
        deduction=RULES["no_ratelimit"] if triggered else 0,
        triggered=triggered,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_posture(
    parse_result: ParseResult,
    trifecta_result: TrifectaResult | None = None,
) -> PostureScore:
    """Compute a deterministic posture score for *parse_result*.

    Args:
        parse_result:    Output of :func:`parser.mcp.parse_mcp_config`.
        trifecta_result: Pre-computed trifecta analysis; computed internally
                         when *None* (avoids duplicate work when the caller
                         already has it).

    Returns:
        :class:`PostureScore` with score in [0, 100] and per-rule breakdown.
    """
    if trifecta_result is None:
        trifecta_result = analyze_trifecta(parse_result)

    nodes = parse_result.nodes

    rule_results: list[RuleResult] = [
        _eval_trifecta_path(trifecta_result),
        _eval_poisoning(trifecta_result),
        _eval_rug_pull(nodes),
        _eval_secret_in_desc(nodes),
        _eval_no_auth(nodes),
        _eval_no_ratelimit(nodes),
    ]

    total_deduction = sum(r.deduction for r in rule_results)
    score = max(0, MAX_SCORE - total_deduction)

    return PostureScore(score=score, rules=rule_results)