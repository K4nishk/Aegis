"""api/metrics.py — Metrics queries Q1-Q3 (KCH-16).

Q1: trifecta aggregate stats per scan (DB)
Q2: posture score rolling average (DB)
Q3: classifier precision/recall/F1 + ambiguity rate from eval harness (no DB)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Q1 — trifecta / scan aggregate stats
# ---------------------------------------------------------------------------


@dataclass
class Q1TrifectaMetrics:
    total_scans: int
    scans_with_trifecta: int
    pct_with_trifecta: float
    total_trifecta_findings: int
    avg_findings_per_scan: float


def query_q1(conn: Any) -> Q1TrifectaMetrics:
    """Return trifecta aggregate stats across all scan_runs visible to the caller.

    Counts scans and trifecta findings stored in scan_runs.metadata JSONB.
    Requires a psycopg2 connection (already has app.user_id set for RLS).
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                COUNT(*) FILTER (
                    WHERE (metadata->>'trifecta_finding_count')::int > 0
                ) AS scans_with_trifecta,
                COALESCE(SUM((metadata->>'trifecta_finding_count')::int), 0)
                    AS total_findings
            FROM scan_runs
            WHERE status = 'completed'
            """
        )
        row = cur.fetchone()

    total_scans: int = row[0] or 0
    scans_with_trifecta: int = row[1] or 0
    total_findings: int = row[2] or 0

    pct = scans_with_trifecta / total_scans if total_scans > 0 else 0.0
    avg = total_findings / total_scans if total_scans > 0 else 0.0

    return Q1TrifectaMetrics(
        total_scans=total_scans,
        scans_with_trifecta=scans_with_trifecta,
        pct_with_trifecta=round(pct, 4),
        total_trifecta_findings=total_findings,
        avg_findings_per_scan=round(avg, 4),
    )


# ---------------------------------------------------------------------------
# Q2 — posture score rolling average
# ---------------------------------------------------------------------------


@dataclass
class Q2DailyAvg:
    date: str  # ISO date "YYYY-MM-DD"
    avg_score: float
    scan_count: int


@dataclass
class Q2PostureMetrics:
    window_days: int
    avg_score: float
    min_score: int
    max_score: int
    scan_count: int
    daily: list[Q2DailyAvg] = field(default_factory=list)


def query_q2(conn: Any, window_days: int = 30) -> Q2PostureMetrics:
    """Return posture score rolling average over the last *window_days* days."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                AVG((metadata->>'score')::int) AS avg_score,
                MIN((metadata->>'score')::int) AS min_score,
                MAX((metadata->>'score')::int) AS max_score,
                COUNT(*) AS scan_count
            FROM scan_runs
            WHERE status = 'completed'
              AND created_at >= NOW() - (%s || ' days')::interval
            """,
            (str(window_days),),
        )
        agg = cur.fetchone()

        cur.execute(
            """
            SELECT
                DATE(created_at) AS day,
                AVG((metadata->>'score')::int) AS avg_score,
                COUNT(*) AS scan_count
            FROM scan_runs
            WHERE status = 'completed'
              AND created_at >= NOW() - (%s || ' days')::interval
            GROUP BY day
            ORDER BY day
            """,
            (str(window_days),),
        )
        daily_rows = cur.fetchall()

    avg_score: float = float(agg[0]) if agg[0] is not None else 0.0
    min_score: int = int(agg[1]) if agg[1] is not None else 0
    max_score: int = int(agg[2]) if agg[2] is not None else 0
    scan_count: int = int(agg[3]) if agg[3] else 0

    daily = [
        Q2DailyAvg(
            date=str(r[0]),
            avg_score=round(float(r[1]), 2),
            scan_count=int(r[2]),
        )
        for r in daily_rows
    ]

    return Q2PostureMetrics(
        window_days=window_days,
        avg_score=round(avg_score, 2),
        min_score=min_score,
        max_score=max_score,
        scan_count=scan_count,
        daily=daily,
    )


# ---------------------------------------------------------------------------
# Q3 — classifier F1 / ambiguity from eval harness (no DB needed)
# ---------------------------------------------------------------------------


@dataclass
class Q3CapMetrics:
    cap: str
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int
    tn: int


@dataclass
class Q3EvalMetrics:
    macro_f1: float
    macro_precision: float
    macro_recall: float
    ambiguity_rate: float
    n_tools: int
    per_cap: list[Q3CapMetrics]
    seeded_bad_missed: list[str]
    # KILL gate booleans (mirroring EvalReport)
    kill_f1: bool
    kill_precision: bool
    kill_ambiguity: bool
    kill_seeded_bad: bool
    any_kill: bool


def query_q3() -> Q3EvalMetrics:
    """Run the eval harness against the gold set and return Q3EvalMetrics.

    Loads gold_labels.json, builds ToolNodes from fixtures, runs trifecta
    classifier, and computes precision/recall/F1 + ambiguity rate.
    No DB connection required.
    """
    from tests.eval_gold.eval_metrics import (
        build_tool_nodes,
        load_gold_labels,
        run_eval,
    )

    gold_path = Path(__file__).parent.parent / "tests" / "eval_gold" / "gold_labels.json"
    fixtures_root = Path(__file__).parent.parent / "tests" / "fixtures" / "mcp"

    entries = load_gold_labels(gold_path)
    nodes = build_tool_nodes(entries, fixtures_root)
    report = run_eval(entries, nodes)

    per_cap = [
        Q3CapMetrics(
            cap=cm.cap,
            precision=round(cm.precision, 4),
            recall=round(cm.recall, 4),
            f1=round(cm.f1, 4),
            tp=cm.tp,
            fp=cm.fp,
            fn=cm.fn,
            tn=cm.tn,
        )
        for cm in report.per_cap.values()
    ]

    return Q3EvalMetrics(
        macro_f1=round(report.macro_f1, 4),
        macro_precision=round(report.macro_precision, 4),
        macro_recall=round(report.macro_recall, 4),
        ambiguity_rate=round(report.ambiguity_rate, 4),
        n_tools=report.n_tools,
        per_cap=per_cap,
        seeded_bad_missed=list(report.seeded_bad_missed),
        kill_f1=report.kill_f1,
        kill_precision=report.kill_precision,
        kill_ambiguity=report.kill_ambiguity,
        kill_seeded_bad=report.kill_seeded_bad,
        any_kill=report.any_kill,
    )
