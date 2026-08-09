"""
analyzer/trifecta.py — Tag each tool with the three trifecta security caps and
detect connected paths where all three are risk-present (HERO feature, KCH-9).

Three security caps (§14 trifecta rule):
  reads_private_data      — tool can read sensitive / private data
  sees_untrusted_content  — tool processes content from untrusted external sources
  can_exfiltrate          — tool can send data to external systems

Each cap has a tri-state value: True | False | "unknown".
Fail-safe rule: unknown → risk-present (same as True for detection purposes).

A *trifecta* is found when a connected component of the tool graph contains at
least one risk-present node for each of the three caps; a BFS walk produces the
ordered path.

Ambiguity rate (fraction of tools with ≥1 unknown cap) is reported to feed the
RA-4 KILL target of <40 %.

Ref: ARD §0 thesis, §14 trifecta rule / KCH-9
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from itertools import permutations
from typing import Literal

from parser.mcp import ParseResult, ToolEdge, ToolNode

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

# Tri-state capability value: True → confirmed, False → absent, "unknown" → ambiguous.
CapValue = bool | Literal["unknown"]

CAP_NAMES: tuple[str, ...] = (
    "reads_private_data",
    "sees_untrusted_content",
    "can_exfiltrate",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CapTag:
    """Security capability tag for one of the three trifecta caps."""

    cap: str  # one of CAP_NAMES
    value: CapValue  # True | False | "unknown"
    confidence: float  # 0.0–1.0
    evidence: list[str] = field(default_factory=list)

    def is_risk_present(self) -> bool:
        """Fail-safe: unknown → risk present (treated the same as True)."""
        return self.value is True or self.value == "unknown"


@dataclass
class SecurityProfile:
    """Three-cap security profile attached to one ToolNode."""

    node_key: str
    reads_private_data: CapTag
    sees_untrusted_content: CapTag
    can_exfiltrate: CapTag

    def cap_tags(self) -> dict[str, CapTag]:
        return {
            "reads_private_data": self.reads_private_data,
            "sees_untrusted_content": self.sees_untrusted_content,
            "can_exfiltrate": self.can_exfiltrate,
        }

    def is_ambiguous(self) -> bool:
        """True if any cap is tagged 'unknown'."""
        return any(t.value == "unknown" for t in self.cap_tags().values())

    def as_dict(self) -> dict:
        """Serialisable dict suitable for JSONB storage."""

        def _tag(t: CapTag) -> dict:
            return {
                "value": t.value,
                "confidence": round(t.confidence, 4),
                "evidence": t.evidence,
            }

        return {cap: _tag(tag) for cap, tag in self.cap_tags().items()}


@dataclass
class TrifectaFinding:
    """A detected trifecta path in the tool graph."""

    path: list[str]  # ordered node_keys from entry to exit
    rpd_node: str  # node_key that contributes reads_private_data
    suc_node: str  # node_key that contributes sees_untrusted_content
    exf_node: str  # node_key that contributes can_exfiltrate
    confidence: float  # min confidence across the three contributing cap tags


@dataclass
class TrifectaResult:
    """Output of :func:`analyze_trifecta`."""

    profiles: dict[str, SecurityProfile]  # node_key → SecurityProfile
    findings: list[TrifectaFinding]
    ambiguity_rate: float  # fraction of tools with ≥1 unknown cap (feeds RA-4)


# ---------------------------------------------------------------------------
# Keyword patterns for cap inference
# ---------------------------------------------------------------------------

_RPD_RE = re.compile(
    r"\b("
    r"private|secret|credential|password|passwd|token|api.?key|apikey|"
    r"auth(?:entication|orization|_token)?|sensitive|confidential|pii|"
    r"personal(?:.?data|.?info(?:rmation)?)?|user.?data|identity|"
    r"certificate|cert|private.?key|access.?key|signing.?key|"
    r"ssh.?key|env(?:ironment)?.?var(?:iable)?|dotenv|\.env"
    r")\b",
    re.I,
)

# Unambiguously-inbound content indicators: the tool fetches or receives content
# from outside the caller's control (web fetch, injection-prone messages, etc.).
# Deliberately excludes email/slack/message — those terms appear on outbound
# tools too (send_email, post_message) and caused 18 false positives in KCH-7.
_SUD_DIRECT_RE = re.compile(
    r"\b("
    r"url|uri|webpage|html|scrape|scraper|browse|browser|"
    r"untrusted|user.?input|user.?message|web.?content|"
    r"inbound|incoming|phishing|"
    r"rss|feed|crawl|spider"
    r")\b",
    re.I,
)

# Web-search tools return external result bodies — an injection vector regardless
# of whether typical inbound-read verbs appear in the description.
_SUD_WEB_SEARCH_RE = re.compile(r"\bweb.?search\b", re.I)

# Inbound-read verbs: the tool is *reading* content, not sending it.
_SUD_READ_VERB_RE = re.compile(
    r"\b(read|retrieve|get|fetch|forward|relay)\b", re.I
)

# Message/channel/content nouns that, when paired with an inbound-read verb,
# signal that the tool ingests content from an external actor.
_SUD_MSG_NOUN_RE = re.compile(
    r"\b(message|channel|dm|thread|issue|comment|conversation|mail|inbox)\b",
    re.I,
)

_EXF_RE = re.compile(
    r"\b("
    r"send|smtp|webhook|notify|notification|publish|upload|share|"
    r"transmit|transfer|export|forward|report|dispatch|broadcast|"
    r"post(?:.?to|.?data)?|deliver|relay"
    r")\b",
    re.I,
)


# ---------------------------------------------------------------------------
# Trifecta tagging
# ---------------------------------------------------------------------------


def _tool_text(node: ToolNode) -> str:
    """Concatenate all searchable text from a ToolNode."""
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


def tag_tool(node: ToolNode) -> SecurityProfile:
    """Assign three security cap tags to *node* using keyword + capability heuristics.

    Heuristic priority (highest wins):
      1. Keyword match in name / description / schema  → high confidence (0.9)
      2. Capability-based inference                    → medium confidence (0.4–0.8)
      3. Default absence                               → low confidence (0.8 False)
    """
    text = _tool_text(node)
    caps = set(node.caps)

    # ------------------------------------------------------------------ rpd --
    rpd_kw = list({m.lower() for m in _RPD_RE.findall(text)})
    if rpd_kw:
        rpd = CapTag(
            "reads_private_data",
            True,
            0.9,
            [f"keyword match: {', '.join(sorted(rpd_kw))}"],
        )
    elif "read" in caps and "fs" in caps:
        rpd = CapTag(
            "reads_private_data",
            "unknown",
            0.5,
            ["reads filesystem; private files may be in scope"],
        )
    elif "read" in caps:
        rpd = CapTag(
            "reads_private_data",
            "unknown",
            0.35,
            ["has read capability; data source is unspecified"],
        )
    else:
        rpd = CapTag("reads_private_data", False, 0.8, [])

    # ------------------------------------------------------------------ suc --
    # Priority 1: unambiguous inbound-content indicator in name/description/schema.
    suc_direct = sorted({m.lower() for m in _SUD_DIRECT_RE.findall(text)})
    # Priority 2: web-search result body (always external content).
    has_web_search = bool(_SUD_WEB_SEARCH_RE.search(text))
    # Priority 3: inbound-read verb + message/channel noun → reads external messages.
    has_read_verb = bool(_SUD_READ_VERB_RE.search(text))
    has_msg_noun = bool(_SUD_MSG_NOUN_RE.search(text))

    if suc_direct:
        suc = CapTag(
            "sees_untrusted_content",
            True,
            0.9,
            [f"inbound content indicator: {', '.join(suc_direct)}"],
        )
    elif has_web_search:
        suc = CapTag(
            "sees_untrusted_content",
            True,
            0.85,
            ["web search result body exposes external content"],
        )
    elif has_read_verb and has_msg_noun:
        verbs = sorted({m.lower() for m in _SUD_READ_VERB_RE.findall(text)})
        nouns = sorted({m.lower() for m in _SUD_MSG_NOUN_RE.findall(text)})
        suc = CapTag(
            "sees_untrusted_content",
            True,
            0.85,
            [f"reads {'+'.join(nouns)} via {'+'.join(verbs)}: external content exposure"],
        )
    else:
        # No evidence of inbound content ingestion; capability fallbacks omitted
        # (network/read caps appear on outbound-only tools and caused 18 FPs — KCH-27).
        suc = CapTag("sees_untrusted_content", False, 0.8, [])

    # ------------------------------------------------------------------ exf --
    exf_kw = list({m.lower() for m in _EXF_RE.findall(text)})
    if exf_kw:
        exf = CapTag(
            "can_exfiltrate",
            True,
            0.9,
            [f"keyword match: {', '.join(sorted(exf_kw))}"],
        )
    elif "network" in caps and ("write" in caps or "exec" in caps):
        exf = CapTag(
            "can_exfiltrate",
            True,
            0.8,
            ["network + write/exec capabilities: can send data externally"],
        )
    elif "exec" in caps:
        exf = CapTag(
            "can_exfiltrate",
            "unknown",
            0.5,
            ["exec capability; spawned processes may exfiltrate data"],
        )
    elif "network" in caps:
        exf = CapTag(
            "can_exfiltrate",
            "unknown",
            0.4,
            ["network capability; outbound transfers are possible"],
        )
    else:
        exf = CapTag("can_exfiltrate", False, 0.8, [])

    return SecurityProfile(
        node_key=node.node_key,
        reads_private_data=rpd,
        sees_untrusted_content=suc,
        can_exfiltrate=exf,
    )


# ---------------------------------------------------------------------------
# Graph utilities
# ---------------------------------------------------------------------------


def _build_adj(
    nodes: list[ToolNode],
    edges: list[ToolEdge],
) -> dict[str, list[str]]:
    """Build an *undirected* adjacency list (all edge types treated equally)."""
    adj: dict[str, list[str]] = {n.node_key: [] for n in nodes}
    for edge in edges:
        if edge.source_key in adj and edge.target_key in adj:
            adj[edge.source_key].append(edge.target_key)
            adj[edge.target_key].append(edge.source_key)
    return adj


def _connected_components(
    all_keys: list[str],
    adj: dict[str, list[str]],
) -> list[frozenset[str]]:
    """BFS over *all_keys* to find connected components."""
    visited: set[str] = set()
    components: list[frozenset[str]] = []
    for key in all_keys:
        if key in visited:
            continue
        component: set[str] = set()
        queue: deque[str] = deque([key])
        visited.add(key)
        while queue:
            node = queue.popleft()
            component.add(node)
            for nb in adj.get(node, []):
                if nb not in visited:
                    visited.add(nb)
                    queue.append(nb)
        components.append(frozenset(component))
    return components


def _bfs_path(
    adj: dict[str, list[str]],
    start: str,
    end: str,
) -> list[str] | None:
    """Return the shortest undirected path from *start* to *end*, or None."""
    if start == end:
        return [start]
    visited = {start}
    queue: deque[list[str]] = deque([[start]])
    while queue:
        path = queue.popleft()
        for nb in adj.get(path[-1], []):
            if nb == end:
                return path + [nb]
            if nb not in visited:
                visited.add(nb)
                queue.append(path + [nb])
    return None


def _path_through_waypoints(
    adj: dict[str, list[str]],
    waypoints: list[str],
) -> list[str] | None:
    """Concatenate BFS segments to visit *waypoints* in order."""
    if not waypoints:
        return []
    result = [waypoints[0]]
    for i in range(len(waypoints) - 1):
        if waypoints[i] == waypoints[i + 1]:
            continue  # same node, no segment needed
        segment = _bfs_path(adj, waypoints[i], waypoints[i + 1])
        if segment is None:
            return None
        result.extend(segment[1:])
    return result


def _find_trifecta_path(
    adj: dict[str, list[str]],
    rpd_key: str,
    suc_key: str,
    exf_key: str,
) -> list[str] | None:
    """Find the shortest path in the graph that visits all three cap nodes.

    Tries the canonical attacker-flow order (suc → rpd → exf) first, then all
    remaining permutations, returning the shortest hit.
    """
    keys = [rpd_key, suc_key, exf_key]
    unique = list(dict.fromkeys(keys))  # preserve order, drop dups

    # Trivial: single node holds all three caps
    if len(unique) == 1:
        return unique

    # Canonical attacker flow: injection → collection → exfiltration
    canonical = [suc_key, rpd_key, exf_key]
    canonical_deduped = [canonical[0]] + [
        canonical[i] for i in range(1, len(canonical)) if canonical[i] != canonical[i - 1]
    ]
    best = _path_through_waypoints(adj, canonical_deduped)

    # Try all remaining permutations; keep the shortest
    for perm in {tuple(p) for p in permutations(unique)}:
        if list(perm) == canonical_deduped:
            continue
        path = _path_through_waypoints(adj, list(perm))
        if path is not None and (best is None or len(path) < len(best)):
            best = path

    return best


# ---------------------------------------------------------------------------
# Trifecta detection
# ---------------------------------------------------------------------------


def _detect_trifecta_paths(
    nodes: list[ToolNode],
    edges: list[ToolEdge],
    profiles: dict[str, SecurityProfile],
) -> list[TrifectaFinding]:
    """Return one TrifectaFinding per connected component that covers all 3 caps."""
    adj = _build_adj(nodes, edges)
    all_keys = [n.node_key for n in nodes]
    components = _connected_components(all_keys, adj)

    findings: list[TrifectaFinding] = []

    for component in components:
        # Best candidates per cap (highest confidence, risk-present only)
        rpd_cands = sorted(
            [k for k in component if profiles[k].reads_private_data.is_risk_present()],
            key=lambda k: -profiles[k].reads_private_data.confidence,
        )
        suc_cands = sorted(
            [k for k in component if profiles[k].sees_untrusted_content.is_risk_present()],
            key=lambda k: -profiles[k].sees_untrusted_content.confidence,
        )
        exf_cands = sorted(
            [k for k in component if profiles[k].can_exfiltrate.is_risk_present()],
            key=lambda k: -profiles[k].can_exfiltrate.confidence,
        )

        if not (rpd_cands and suc_cands and exf_cands):
            continue

        # Search top-3 candidates per cap for best (highest-confidence) path
        best: TrifectaFinding | None = None
        for rpd_key in rpd_cands[:3]:
            for suc_key in suc_cands[:3]:
                for exf_key in exf_cands[:3]:
                    path = _find_trifecta_path(adj, rpd_key, suc_key, exf_key)
                    if path is None:
                        continue
                    conf = min(
                        profiles[rpd_key].reads_private_data.confidence,
                        profiles[suc_key].sees_untrusted_content.confidence,
                        profiles[exf_key].can_exfiltrate.confidence,
                    )
                    if best is None or conf > best.confidence:
                        best = TrifectaFinding(
                            path=path,
                            rpd_node=rpd_key,
                            suc_node=suc_key,
                            exf_node=exf_key,
                            confidence=conf,
                        )

        if best is not None:
            findings.append(best)

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_trifecta(result: ParseResult) -> TrifectaResult:
    """Tag all nodes in *result* with security caps and detect trifecta paths.

    Args:
        result: Parsed tool graph from :func:`parser.mcp.parse_mcp_config`.

    Returns:
        :class:`TrifectaResult` containing per-node profiles, findings, and the
        ambiguity rate (fraction of tools with ≥1 unknown cap, feeds RA-4).
    """
    profiles = {node.node_key: tag_tool(node) for node in result.nodes}

    findings = _detect_trifecta_paths(result.nodes, result.edges, profiles)

    n = len(profiles)
    ambiguous = sum(1 for p in profiles.values() if p.is_ambiguous())
    ambiguity_rate = ambiguous / n if n > 0 else 0.0

    return TrifectaResult(
        profiles=profiles,
        findings=findings,
        ambiguity_rate=ambiguity_rate,
    )
