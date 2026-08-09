"""api/models.py — Pydantic request/response schemas (KCH-11)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# POST /scans
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    mcp_json: dict[str, Any] = Field(..., description="Raw MCP config object")
    label: str | None = Field(None, description="Human-readable scan label")


class ScanResponse(BaseModel):
    id: str
    status: str
    label: str | None = None
    score: int
    triggered_rules: list[str]
    trifecta_finding_count: int
    warnings: list[str]
    created_at: str
    completed_at: str | None = None


# ---------------------------------------------------------------------------
# GET /scans/{id}/report
# ---------------------------------------------------------------------------


class RuleResultOut(BaseModel):
    rule: str
    deduction: int
    triggered: bool
    evidence: list[str]


class ReportResponse(BaseModel):
    scan_id: str
    score: int
    triggered_rules: list[str]
    rules: list[RuleResultOut]
    trifecta_findings: list[dict[str, Any]]
    warnings: list[str]
    fmt: str = "json"


# ---------------------------------------------------------------------------
# GET /scans/{id}/aibom
# ---------------------------------------------------------------------------


class AiBomComponent(BaseModel):
    node_key: str
    tool_name: str
    server_name: str
    caps: list[str]
    def_hash: str
    security_caps: dict[str, Any] | None = None


class AiBomResponse(BaseModel):
    scan_id: str
    components: list[AiBomComponent]


# ---------------------------------------------------------------------------
# POST /gate
# ---------------------------------------------------------------------------


class GateRequest(BaseModel):
    scan_id: str
    min_score: int = Field(70, ge=0, le=100)


class GateResponse(BaseModel):
    scan_id: str
    score: int
    min_score: int
    passed: bool
    triggered_rules: list[str]
