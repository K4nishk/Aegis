"""
tests/eval_gold/eval_metrics.py — Precision / recall / F1 evaluation for the
trifecta static classifier against the hand-labeled gold set (KCH-7).

Public API:
    load_gold_labels(path) -> list[GoldEntry]
    build_tool_nodes(entries, fixtures_root) -> dict[str, ToolNode]
    run_eval(entries, nodes) -> EvalReport
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from analyzer.trifecta import CAP_NAMES, SecurityProfile, tag_tool
from parser.mcp import ToolNode

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

CAP_NAMES_LIST: list[str] = list(CAP_NAMES)


@dataclass
class GoldEntry:
    node_key: str
    ground_truth: dict[str, bool]  # cap -> True/False
    seeded_bad: bool
    notes: str = ""


@dataclass
class CapMetrics:
    cap: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


@dataclass
class EvalReport:
    per_cap: dict[str, CapMetrics]
    ambiguity_rate: float
    n_tools: int
    seeded_bad_missed: list[str]  # node_keys of seeded-bad tools where a True cap was missed

    # KILL gate conditions (computed on demand)
    @property
    def macro_precision(self) -> float:
        caps = list(self.per_cap.values())
        return sum(c.precision for c in caps) / len(caps)

    @property
    def macro_recall(self) -> float:
        caps = list(self.per_cap.values())
        return sum(c.recall for c in caps) / len(caps)

    @property
    def macro_f1(self) -> float:
        caps = list(self.per_cap.values())
        return sum(c.f1 for c in caps) / len(caps)

    @property
    def kill_precision(self) -> bool:
        """True iff KILL gate triggered: macro precision < 0.60."""
        return self.macro_precision < 0.60

    @property
    def kill_f1(self) -> bool:
        """True iff KILL gate triggered: macro F1 < 0.70."""
        return self.macro_f1 < 0.70

    @property
    def kill_seeded_bad(self) -> bool:
        """True iff KILL gate triggered: at least one seeded-bad cap missed."""
        return len(self.seeded_bad_missed) > 0

    @property
    def kill_ambiguity(self) -> bool:
        """True iff KILL gate triggered: ambiguity rate > 0.40."""
        return self.ambiguity_rate > 0.40

    @property
    def any_kill(self) -> bool:
        return self.kill_precision or self.kill_f1 or self.kill_seeded_bad or self.kill_ambiguity

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        lines.append(f"n_tools          = {self.n_tools}")
        lines.append(
            f"ambiguity_rate   = {self.ambiguity_rate:.1%}  (KILL if >40%: {'TRIGGERED' if self.kill_ambiguity else 'ok'})"
        )
        lines.append("")
        lines.append(
            f"{'cap':<26} {'P':>7} {'R':>7} {'F1':>7} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}"
        )
        lines.append("-" * 75)
        for c in self.per_cap.values():
            lines.append(
                f"{c.cap:<26} {c.precision:>7.1%} {c.recall:>7.1%} {c.f1:>7.1%}"
                f" {c.tp:>4} {c.fp:>4} {c.fn:>4} {c.tn:>4}"
            )
        lines.append("-" * 75)
        lines.append(
            f"{'MACRO':<26} {self.macro_precision:>7.1%} {self.macro_recall:>7.1%} {self.macro_f1:>7.1%}"
        )
        lines.append("")
        lines.append(
            f"macro_precision  = {self.macro_precision:.1%}  (KILL if <60%: {'TRIGGERED' if self.kill_precision else 'ok'})"
        )
        lines.append(
            f"macro_f1         = {self.macro_f1:.1%}  (KILL if <70%: {'TRIGGERED' if self.kill_f1 else 'ok'})"
        )
        lines.append(
            f"seeded_bad_missed= {len(self.seeded_bad_missed)}  (KILL if >0: {'TRIGGERED' if self.kill_seeded_bad else 'ok'})"
        )
        if self.seeded_bad_missed:
            for item in self.seeded_bad_missed:
                lines.append(f"  - {item}")
        lines.append("")
        lines.append(f"VERDICT          = {'KILL / PIVOT' if self.any_kill else 'GO'}")
        return lines


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_gold_labels(path: str | Path) -> list[GoldEntry]:
    """Load gold_labels.json and return a list of GoldEntry objects."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries: list[GoldEntry] = []
    for item in data["tools"]:
        gt = item["ground_truth"]
        entries.append(
            GoldEntry(
                node_key=item["node_key"],
                ground_truth={k: bool(v) for k, v in gt.items()},
                seeded_bad=bool(item.get("seeded_bad", False)),
                notes=item.get("notes", ""),
            )
        )
    return entries


# ---------------------------------------------------------------------------
# ToolNode builder
# ---------------------------------------------------------------------------


def _server_from_key(node_key: str) -> str:
    parts = node_key.split("/", 1)
    return parts[0] if len(parts) == 2 else ""


def _tool_name_from_key(node_key: str) -> str:
    parts = node_key.split("/", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def build_tool_nodes(
    entries: list[GoldEntry],
    fixtures_root: str | Path,
) -> dict[str, ToolNode]:
    """
    Parse all fixture files listed in gold_labels.json and return a mapping
    node_key -> ToolNode for each entry in the gold set.
    """
    from parser.mcp import parse_mcp_file

    fixtures_root = Path(fixtures_root)
    # repo root is 3 levels up from this file (tests/eval_gold/eval_metrics.py)
    repo_root = Path(__file__).parent.parent.parent
    gold_path = Path(__file__).parent / "gold_labels.json"
    data = json.loads(gold_path.read_text(encoding="utf-8"))

    # Build a unified lookup: node_key -> ToolNode from all fixture files
    node_map: dict[str, ToolNode] = {}
    for rel_path in data.get("fixture_files", []):
        fixture_path = repo_root / rel_path
        if not fixture_path.exists():
            raise FileNotFoundError(f"Fixture not found: {fixture_path}")
        result = parse_mcp_file(fixture_path)
        for node in result.nodes:
            node_map[node.node_key] = node

    # Verify every gold entry has a matching node
    missing = [e.node_key for e in entries if e.node_key not in node_map]
    if missing:
        raise ValueError(f"Gold entries not found in fixtures: {missing}")

    return {e.node_key: node_map[e.node_key] for e in entries}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def run_eval(
    entries: list[GoldEntry],
    nodes: dict[str, ToolNode],
) -> EvalReport:
    """
    Tag every node with the trifecta classifier, compare against gold labels,
    and return an EvalReport.

    Prediction convention (fail-safe):
        CapTag.value == True    → risk-present (predicted positive)
        CapTag.value == "unknown" → risk-present (fail-safe → predicted positive)
        CapTag.value == False   → not risk-present (predicted negative)
    """
    per_cap: dict[str, CapMetrics] = {cap: CapMetrics(cap=cap) for cap in CAP_NAMES}
    n_ambiguous = 0
    seeded_bad_missed: list[str] = []

    for entry in entries:
        node = nodes[entry.node_key]
        profile: SecurityProfile = tag_tool(node)

        # Track ambiguity
        if profile.is_ambiguous():
            n_ambiguous += 1

        # Per-cap confusion matrix
        missed_caps: list[str] = []
        for cap in CAP_NAMES:
            tag = profile.cap_tags()[cap]
            predicted_positive = tag.is_risk_present()  # True or "unknown" → positive
            actual_positive = entry.ground_truth[cap]

            cm = per_cap[cap]
            if predicted_positive and actual_positive:
                cm.tp += 1
            elif predicted_positive and not actual_positive:
                cm.fp += 1
            elif not predicted_positive and actual_positive:
                cm.fn += 1
                missed_caps.append(cap)
            else:
                cm.tn += 1

        # KILL check: seeded-bad tool must have all True caps detected
        if entry.seeded_bad and missed_caps:
            seeded_bad_missed.append(f"{entry.node_key} (missed caps: {', '.join(missed_caps)})")

    ambiguity_rate = n_ambiguous / len(entries) if entries else 0.0

    return EvalReport(
        per_cap=per_cap,
        ambiguity_rate=ambiguity_rate,
        n_tools=len(entries),
        seeded_bad_missed=seeded_bad_missed,
    )
