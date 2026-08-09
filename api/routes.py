"""api/routes.py — All five Aegis API endpoints (KCH-11/KCH-17).

Endpoints:
  POST /scans                       — parse mcp_json, analyse, persist, return result
  GET  /scans/{scan_id}             — retrieve scan summary
  GET  /scans/{scan_id}/report?fmt= — full posture report (json | text)
  GET  /scans/{scan_id}/aibom       — AI Bill of Materials
  POST /gate                        — pass/fail gate check

KCH-17 authorization defence in two layers:
  1. DB (RLS): every connection has SET LOCAL app.user_id so the DB itself
     refuses rows the caller doesn't own.
  2. API: every query also filters by owner_id = <current_user_id>.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import psycopg2.extras  # type: ignore[import-untyped]
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from analyzer.posture import score_posture
from analyzer.trifecta import analyze_trifecta
from api.deps import get_authed_db, get_current_user
from api.models import (
    AiBomComponent,
    AiBomResponse,
    GateRequest,
    GateResponse,
    ReportResponse,
    RuleResultOut,
    ScanRequest,
    ScanResponse,
)
from api.rate_limit import gate_rate_limit, scans_rate_limit
from parser.mcp import parse_mcp_config
from parser.persist import persist_graph

router = APIRouter(dependencies=[Depends(get_current_user)])  # noqa: B008


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


# ---------------------------------------------------------------------------
# POST /scans
# ---------------------------------------------------------------------------


@router.post("/scans", response_model=ScanResponse, status_code=201, dependencies=[Depends(scans_rate_limit)])  # noqa: B008
async def create_scan(
    body: ScanRequest,
    request: Request,
    db: Any = Depends(get_authed_db),  # noqa: B008
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> ScanResponse:
    """Parse *mcp_json*, run trifecta + posture analysis, persist to DB."""
    label = body.label or "inline"
    now = _utcnow()
    scan_id = str(uuid.uuid4())

    # --- Analysis (always, even without DB) ---
    graph = parse_mcp_config(body.mcp_json, source_name=label)
    trifecta = analyze_trifecta(graph)
    posture = score_posture(graph, trifecta)

    # Build serialisable metadata payload
    metadata: dict[str, Any] = {
        "label": label,
        "score": posture.score,
        "triggered_rules": posture.triggered_rules,
        "rules": [
            {
                "rule": r.rule,
                "deduction": r.deduction,
                "triggered": r.triggered,
                "evidence": r.evidence,
            }
            for r in posture.rules
        ],
        "trifecta_finding_count": len(trifecta.findings),
        "trifecta_findings": [
            {
                "path": f.path,
                "rpd_node": f.rpd_node,
                "suc_node": f.suc_node,
                "exf_node": f.exf_node,
                "confidence": f.confidence,
            }
            for f in trifecta.findings
        ],
        "trifecta_profiles": {
            k: v.as_dict() for k, v in trifecta.profiles.items()
        },
        "warnings": graph.warnings,
    }

    completed_at: str | None = None

    # --- Persist (best-effort when DB is available) ---
    if db is not None:
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (id, status, target, metadata, created_at, owner_id)
                VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                """,
                (scan_id, "running", label, json.dumps(metadata), now, str(user_id)),
            )

        try:
            persist_graph(db, scan_id, graph)

            # Backfill security_caps into tool_graph_nodes
            with db.cursor() as cur:
                for node_key, profile in trifecta.profiles.items():
                    cur.execute(
                        """
                        UPDATE tool_graph_nodes
                        SET security_caps = %s::jsonb
                        WHERE scan_run_id = %s AND node_key = %s
                        """,
                        (json.dumps(profile.as_dict()), scan_id, node_key),
                    )

            done = _utcnow()
            with db.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_runs
                    SET status = %s, completed_at = %s, metadata = %s::jsonb
                    WHERE id = %s AND owner_id = %s
                    """,
                    ("completed", done, json.dumps(metadata), scan_id, str(user_id)),
                )
            completed_at = _iso(done)

        except Exception:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE scan_runs SET status = 'failed' WHERE id = %s AND owner_id = %s",
                    (scan_id, str(user_id)),
                )
            raise

    # Expose resource_id to audit middleware
    request.state.audit_resource_id = scan_id

    return ScanResponse(
        id=scan_id,
        status="completed" if db is not None else "ephemeral",
        label=label,
        score=posture.score,
        triggered_rules=posture.triggered_rules,
        trifecta_finding_count=len(trifecta.findings),
        warnings=graph.warnings,
        created_at=_iso(now),
        completed_at=completed_at,
    )


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}
# ---------------------------------------------------------------------------


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    request: Request,
    db: Any = Depends(get_authed_db),  # noqa: B008
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> ScanResponse:
    if db is None:
        raise HTTPException(503, "Database not available")

    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, status, target, metadata, created_at, completed_at
            FROM scan_runs
            WHERE id = %s AND owner_id = %s
            """,
            (scan_id, str(user_id)),
        )
        row = cur.fetchone()

    if row is None:
        raise HTTPException(404, f"Scan {scan_id} not found")

    meta: dict[str, Any] = row["metadata"] or {}
    request.state.audit_resource_id = scan_id

    return ScanResponse(
        id=str(row["id"]),
        status=row["status"],
        label=meta.get("label"),
        score=meta.get("score", 0),
        triggered_rules=meta.get("triggered_rules", []),
        trifecta_finding_count=meta.get("trifecta_finding_count", 0),
        warnings=meta.get("warnings", []),
        created_at=_iso(row["created_at"]),
        completed_at=_iso(row["completed_at"]) if row["completed_at"] else None,
    )


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/report
# ---------------------------------------------------------------------------


@router.get("/scans/{scan_id}/report")
async def get_report(
    scan_id: str,
    request: Request,
    fmt: str = Query("json", pattern="^(json|text)$"),
    db: Any = Depends(get_authed_db),  # noqa: B008
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> Any:
    if db is None:
        raise HTTPException(503, "Database not available")

    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT metadata FROM scan_runs WHERE id = %s AND owner_id = %s",
            (scan_id, str(user_id)),
        )
        row = cur.fetchone()

    if row is None:
        raise HTTPException(404, f"Scan {scan_id} not found")

    meta: dict[str, Any] = row["metadata"] or {}
    request.state.audit_resource_id = scan_id

    rules = [
        RuleResultOut(
            rule=r["rule"],
            deduction=r["deduction"],
            triggered=r["triggered"],
            evidence=r["evidence"],
        )
        for r in meta.get("rules", [])
    ]

    report = ReportResponse(
        scan_id=scan_id,
        score=meta.get("score", 0),
        triggered_rules=meta.get("triggered_rules", []),
        rules=rules,
        trifecta_findings=meta.get("trifecta_findings", []),
        warnings=meta.get("warnings", []),
        fmt=fmt,
    )

    if fmt == "text":
        lines = [
            f"Aegis Posture Report — scan {scan_id}",
            f"Score: {report.score}/100",
            f"Triggered rules: {', '.join(report.triggered_rules) or 'none'}",
            "",
            "--- Rules ---",
        ]
        for r in report.rules:
            status = "TRIGGERED" if r.triggered else "ok"
            lines.append(f"  [{status:9s}] {r.rule:<20} -{r.deduction:3d} pts")
            for ev in r.evidence:
                lines.append(f"             {ev}")
        lines += [
            "",
            f"Trifecta findings: {len(report.trifecta_findings)}",
        ]
        for f in report.trifecta_findings:
            lines.append(f"  path: {' → '.join(f['path'])}")
        if report.warnings:
            lines += ["", "--- Parse warnings ---"]
            lines += [f"  {w}" for w in report.warnings]
        return PlainTextResponse("\n".join(lines))

    return report


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/aibom
# ---------------------------------------------------------------------------


@router.get("/scans/{scan_id}/aibom", response_model=AiBomResponse)
async def get_aibom(
    scan_id: str,
    request: Request,
    db: Any = Depends(get_authed_db),  # noqa: B008
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> AiBomResponse:
    if db is None:
        raise HTTPException(503, "Database not available")

    # Verify scan exists and belongs to the caller (API-level ownership check)
    with db.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM scan_runs WHERE id = %s AND owner_id = %s",
            (scan_id, str(user_id)),
        )
        if cur.fetchone() is None:
            raise HTTPException(404, f"Scan {scan_id} not found")

    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT node_key, tool_name, server_name, caps, def_hash, security_caps
            FROM tool_graph_nodes
            WHERE scan_run_id = %s
            ORDER BY node_key
            """,
            (scan_id,),
        )
        rows = cur.fetchall()

    request.state.audit_resource_id = scan_id

    components = [
        AiBomComponent(
            node_key=r["node_key"],
            tool_name=r["tool_name"],
            server_name=r["server_name"] or "",
            caps=r["caps"] if isinstance(r["caps"], list) else json.loads(r["caps"] or "[]"),
            def_hash=r["def_hash"] or "",
            security_caps=r["security_caps"],
        )
        for r in rows
    ]

    return AiBomResponse(scan_id=scan_id, components=components)


# ---------------------------------------------------------------------------
# POST /gate
# ---------------------------------------------------------------------------


@router.post("/gate", response_model=GateResponse, dependencies=[Depends(gate_rate_limit)])  # noqa: B008
async def gate(
    body: GateRequest,
    request: Request,
    db: Any = Depends(get_authed_db),  # noqa: B008
    user_id: uuid.UUID = Depends(get_current_user),  # noqa: B008
) -> GateResponse:
    if db is None:
        raise HTTPException(503, "Database not available")

    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT metadata FROM scan_runs
            WHERE id = %s AND status = 'completed' AND owner_id = %s
            """,
            (body.scan_id, str(user_id)),
        )
        row = cur.fetchone()

    if row is None:
        raise HTTPException(404, f"Completed scan {body.scan_id} not found")

    meta: dict[str, Any] = row["metadata"] or {}
    score = meta.get("score", 0)
    triggered = meta.get("triggered_rules", [])
    request.state.audit_resource_id = body.scan_id

    return GateResponse(
        scan_id=body.scan_id,
        score=score,
        min_score=body.min_score,
        passed=score >= body.min_score,
        triggered_rules=triggered,
    )
