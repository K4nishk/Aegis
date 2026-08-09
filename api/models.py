"""api/models.py — Pydantic request/response schemas (KCH-11/KCH-18).

KCH-18: every request model uses extra='forbid' (whitelist fields) so hostile
extra-field payloads are rejected with HTTP 422. Price/role/permission fields
are never accepted from the client — those are always server-derived.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# POST /scans
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Strict schema for POST /scans. Extra fields are rejected (422)."""

    model_config = ConfigDict(extra="forbid")

    mcp_json: dict[str, Any] = Field(..., description="Raw MCP config object")
    label: str | None = Field(
        None,
        max_length=256,
        description="Human-readable scan label (optional, ≤256 chars)",
    )


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
    """Strict schema for POST /gate. Extra fields are rejected (422)."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="UUID of a completed scan run")
    min_score: int = Field(70, ge=0, le=100, description="Pass threshold (0–100)")

    @field_validator("scan_id")
    @classmethod
    def _validate_scan_id(cls, v: str) -> str:
        try:
            uuid.UUID(v)
        except ValueError as exc:
            raise ValueError("scan_id must be a valid UUID") from exc
        return v


class GateResponse(BaseModel):
    scan_id: str
    score: int
    min_score: int
    passed: bool
    triggered_rules: list[str]
