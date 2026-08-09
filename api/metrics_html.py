"""api/metrics_html.py — HTML review board for metrics dashboard (KCH-16)."""

from __future__ import annotations

from typing import Any

_KILL_THRESHOLD_F1 = 0.70
_KILL_THRESHOLD_PRECISION = 0.60
_KILL_THRESHOLD_AMBIGUITY = 0.40

_CSS = """
body { font-family: system-ui, sans-serif; margin: 0; padding: 0; background: #f4f6f9; color: #222; }
.banner { background: #1a1a2e; color: #fff; padding: 18px 32px; font-size: 1.4rem; font-weight: bold; letter-spacing: 1px; }
.banner span { color: #e94560; }
.container { max-width: 960px; margin: 32px auto; padding: 0 16px; }
h2 { margin-top: 32px; border-bottom: 2px solid #e94560; padding-bottom: 6px; color: #1a1a2e; }
.card { background: #fff; border-radius: 8px; padding: 20px 28px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.metric-row { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 8px; }
.metric { flex: 1; min-width: 140px; background: #f0f4ff; border-radius: 6px; padding: 14px 18px; }
.metric .label { font-size: 0.8rem; color: #555; margin-bottom: 4px; }
.metric .value { font-size: 1.5rem; font-weight: bold; color: #1a1a2e; }
table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
th { background: #1a1a2e; color: #fff; padding: 8px 12px; text-align: left; }
td { padding: 8px 12px; border-bottom: 1px solid #eee; }
tr:last-child td { border-bottom: none; }
.ok { color: #16a34a; font-weight: bold; }
.kill { color: #dc2626; font-weight: bold; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.82rem; font-weight: bold; }
.badge-go { background: #d1fae5; color: #065f46; }
.badge-kill { background: #fee2e2; color: #991b1b; }
.no-db { color: #888; font-style: italic; font-size: 0.95rem; }
footer { text-align: center; color: #aaa; font-size: 0.8rem; padding: 32px; }
"""


def render_metrics_html(dashboard: dict[str, Any]) -> str:
    """Render the metrics review board as a self-contained HTML string."""
    generated_at = dashboard.get("generated_at", "")
    window_days = dashboard.get("window_days", 30)
    q1 = dashboard.get("q1")
    q2 = dashboard.get("q2")
    q3 = dashboard.get("q3", {})

    # ------------------------------------------------------------------
    # Q1 block
    # ------------------------------------------------------------------
    if q1:
        q1_html = f"""
        <div class="metric-row">
          <div class="metric"><div class="label">Total Scans</div><div class="value">{q1["total_scans"]}</div></div>
          <div class="metric"><div class="label">Scans w/ Trifecta</div><div class="value">{q1["scans_with_trifecta"]}</div></div>
          <div class="metric"><div class="label">% with Trifecta</div><div class="value">{q1["pct_with_trifecta"]:.1%}</div></div>
          <div class="metric"><div class="label">Total Findings</div><div class="value">{q1["total_trifecta_findings"]}</div></div>
          <div class="metric"><div class="label">Avg / Scan</div><div class="value">{q1["avg_findings_per_scan"]:.2f}</div></div>
        </div>
        """
    else:
        q1_html = '<p class="no-db">No database connection — Q1 data unavailable.</p>'

    # ------------------------------------------------------------------
    # Q2 block
    # ------------------------------------------------------------------
    if q2:
        daily_rows = ""
        for d in q2.get("daily", []):
            daily_rows += f"<tr><td>{d['date']}</td><td>{d['avg_score']:.1f}</td><td>{d['scan_count']}</td></tr>"
        if not daily_rows:
            daily_rows = '<tr><td colspan="3" style="color:#888">No data in window</td></tr>'

        q2_html = f"""
        <div class="metric-row">
          <div class="metric"><div class="label">Window</div><div class="value">{q2["window_days"]}d</div></div>
          <div class="metric"><div class="label">Avg Score</div><div class="value">{q2["avg_score"]:.1f}</div></div>
          <div class="metric"><div class="label">Min Score</div><div class="value">{q2["min_score"]}</div></div>
          <div class="metric"><div class="label">Max Score</div><div class="value">{q2["max_score"]}</div></div>
          <div class="metric"><div class="label">Scans in Window</div><div class="value">{q2["scan_count"]}</div></div>
        </div>
        <table>
          <thead><tr><th>Date</th><th>Avg Score</th><th>Scans</th></tr></thead>
          <tbody>{daily_rows}</tbody>
        </table>
        """
    else:
        q2_html = '<p class="no-db">No database connection — Q2 data unavailable.</p>'

    # ------------------------------------------------------------------
    # Q3 block
    # ------------------------------------------------------------------
    any_kill = q3.get("any_kill", False)
    verdict_badge = (
        '<span class="badge badge-kill">KILL / PIVOT</span>'
        if any_kill
        else '<span class="badge badge-go">GO</span>'
    )

    def _gate(triggered: bool, label: str) -> str:
        cls = "kill" if triggered else "ok"
        text = "TRIGGERED" if triggered else "ok"
        return f'<span class="{cls}">{text}</span> {label}'

    cap_rows = ""
    for c in q3.get("per_cap", []):
        cap_rows += (
            f"<tr><td>{c['cap']}</td>"
            f"<td>{c['precision']:.1%}</td>"
            f"<td>{c['recall']:.1%}</td>"
            f"<td>{c['f1']:.1%}</td>"
            f"<td>{c['tp']}</td><td>{c['fp']}</td><td>{c['fn']}</td><td>{c['tn']}</td></tr>"
        )

    macro_f1 = q3.get("macro_f1", 0.0)
    macro_p = q3.get("macro_precision", 0.0)
    macro_r = q3.get("macro_recall", 0.0)
    ambiguity = q3.get("ambiguity_rate", 0.0)
    n_tools = q3.get("n_tools", 0)
    seeded_missed = q3.get("seeded_bad_missed", [])

    cap_rows += (
        f"<tr style='font-weight:bold;background:#f0f4ff'>"
        f"<td>MACRO</td>"
        f"<td>{macro_p:.1%}</td>"
        f"<td>{macro_r:.1%}</td>"
        f"<td>{macro_f1:.1%}</td>"
        f"<td colspan='4'></td></tr>"
    )

    seeded_list = (
        "<ul>" + "".join(f"<li>{s}</li>" for s in seeded_missed) + "</ul>" if seeded_missed else ""
    )

    q3_html = f"""
    <div style="margin-bottom:12px">Verdict: {verdict_badge} &nbsp;|&nbsp; n_tools={n_tools}</div>
    <table>
      <thead>
        <tr><th>Cap</th><th>Precision</th><th>Recall</th><th>F1</th>
            <th>TP</th><th>FP</th><th>FN</th><th>TN</th></tr>
      </thead>
      <tbody>{cap_rows}</tbody>
    </table>
    <div style="margin-top:14px">
      <p>{_gate(q3.get("kill_f1", False), f"macro F1 {macro_f1:.1%} (KILL if &lt; {_KILL_THRESHOLD_F1:.0%})")}</p>
      <p>{_gate(q3.get("kill_precision", False), f"macro Precision {macro_p:.1%} (KILL if &lt; {_KILL_THRESHOLD_PRECISION:.0%})")}</p>
      <p>{_gate(q3.get("kill_ambiguity", False), f"ambiguity rate {ambiguity:.1%} (KILL if &gt; {_KILL_THRESHOLD_AMBIGUITY:.0%})")}</p>
      <p>{_gate(q3.get("kill_seeded_bad", False), f"seeded_bad missed: {len(seeded_missed)} (KILL if &gt; 0)")}</p>
    </div>
    {seeded_list}
    """

    # ------------------------------------------------------------------
    # Assemble full page
    # ------------------------------------------------------------------
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Aegis Metrics Review Board</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="banner">
    <span>AEGIS</span> — Metrics Review Board
    <span style="font-size:0.8rem;font-weight:normal;margin-left:16px;color:#aaa">generated {generated_at}</span>
  </div>
  <div class="container">

    <h2>Q1 — Trifecta / Scan Stats</h2>
    <div class="card">{q1_html}</div>

    <h2>Q2 — Posture Score Moving Average ({window_days}-day window)</h2>
    <div class="card">{q2_html}</div>

    <h2>Q3 — Classifier Precision / Recall / F1 (gold set)</h2>
    <div class="card">{q3_html}</div>

  </div>
  <footer>Aegis &copy; 2026 — prototype/PoV</footer>
</body>
</html>"""
