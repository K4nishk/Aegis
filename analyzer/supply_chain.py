"""
analyzer/supply_chain.py — Detect unpinned MCP server package references (SEC-4 / KCH-20).

An *unpinned* server invocation is one where the package version cannot be verified
at install time, leaving the deployment open to silent substitution or rug-pull attacks.

Patterns flagged (HIGH severity):
  - npx -y <pkg>            without an exact @version suffix   (e.g. "@mcp/server-github")
  - npx <pkg>               any npx call without a @x.y.z pin
  - uvx <pkg>               without ==x.y.z pin

Patterns flagged (MEDIUM severity):
  - uvx <pkg>@<tag>         version is a tag/ref, not a semver
  - npx <pkg>@<branch>      same as above

Ref: ARD §6.1 SEC-4 / KCH-20
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Semver-like: x.y.z or x.y or x (all numeric segments)
_SEMVER_RE = re.compile(r"^\d+(\.\d+){0,2}$")

# npm scoped package + optional @version:  @scope/name@1.2.3 or name@1.2.3
_NPM_PKG_RE = re.compile(r"^(?:@[^/]+/)?[^@\s]+(?:@(.+))?$")

# uvx pkg==version
_UVX_PINNED_RE = re.compile(r"^[^=\s]+==[^\s]+$")
# uvx pkg>=version or similar constraint
_UVX_CONSTRAINED_RE = re.compile(r"^[^=<>!\s]+[=<>!]")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SupplyChainFinding:
    """One detected supply-chain risk in an MCP server definition."""

    server_name: str
    command: str  # e.g. "npx", "uvx"
    args: list[str]
    risk: str  # "unpinned_version" | "tag_not_semver" | "auto_install"
    severity: str  # "HIGH" | "MEDIUM"
    detail: str  # human-readable explanation


@dataclass
class SupplyChainResult:
    """Aggregate result of a supply-chain scan over an MCP config."""

    findings: list[SupplyChainFinding] = field(default_factory=list)
    servers_scanned: int = 0
    clean: bool = True  # False when any HIGH finding present

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")


# ---------------------------------------------------------------------------
# Inspection helpers
# ---------------------------------------------------------------------------


def _check_npm_args(args: list[Any]) -> tuple[str, str] | None:
    """
    Return (risk, detail) if npm args indicate an unpinned package, else None.

    Normalises: npx [-y] [--] <pkg[@version]> [extra-args…]
    """
    if not args:
        return None

    str_args = [str(a) for a in args]
    # Strip flags like -y, --yes, --no-install, -- etc.
    pkg_candidates = [a for a in str_args if not a.startswith("-")]
    if not pkg_candidates:
        return ("unpinned_version", "npx with no package argument")

    pkg = pkg_candidates[0]

    # Extract version portion from pkg@version
    m = _NPM_PKG_RE.match(pkg)
    if not m:
        return None  # Can't parse; don't flag

    version_part = m.group(1)  # None if no @version

    if version_part is None:
        # Completely unpinned
        return (
            "unpinned_version",
            f"Package '{pkg}' has no version pin — resolved at runtime, "
            "enabling silent substitution attacks (cf. postmark-mcp CVE-2025-6514).",
        )

    if not _SEMVER_RE.match(version_part):
        # Has a version-like suffix but it's a dist-tag or branch, not semver
        return (
            "tag_not_semver",
            f"Package '{pkg}' uses tag/ref '{version_part}' instead of a "
            "semver pin — tag can be moved to a malicious version.",
        )

    return None  # Pinned to semver — OK


def _check_uvx_args(args: list[Any]) -> tuple[str, str] | None:
    """Return (risk, detail) if uvx args indicate an unpinned package, else None."""
    if not args:
        return None

    str_args = [str(a) for a in args]
    # Strip flags
    pkg_candidates = [a for a in str_args if not a.startswith("-")]
    if not pkg_candidates:
        return ("unpinned_version", "uvx with no package argument")

    pkg = pkg_candidates[0]

    if _UVX_PINNED_RE.match(pkg):
        return None  # pkg==x.y.z — exact pin

    if _UVX_CONSTRAINED_RE.match(pkg):
        # Has a constraint but not exact pin
        return (
            "tag_not_semver",
            f"Package '{pkg}' uses a range constraint rather than an exact pin; "
            "prefer pkg==x.y.z to guarantee reproducibility.",
        )

    # No pin at all
    return (
        "unpinned_version",
        f"Package '{pkg}' has no version pin — resolved at runtime, "
        "enabling silent substitution attacks.",
    )


def _has_auto_install_flag(args: list[Any]) -> bool:
    """Detect -y / --yes flags that silently approve package installation."""
    return any(str(a) in ("-y", "--yes") for a in args)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_mcp_config(mcp_json: dict[str, Any]) -> SupplyChainResult:
    """
    Scan an MCP config dict for unpinned server package references.

    Accepts all formats supported by parser.mcp.parse_mcp_config:
      - {"mcpServers": {name: {command, args, …}}}
      - {"servers": {name: {command, args, …}}}
      - single-server: {"command": …, "args": …}

    Returns a SupplyChainResult with one SupplyChainFinding per detected risk.
    """
    result = SupplyChainResult()

    servers: dict[str, Any] = {}

    raw_servers = mcp_json.get("mcpServers") or mcp_json.get("servers")
    if isinstance(raw_servers, dict):
        servers = raw_servers
    elif "command" in mcp_json:
        # Single-server shorthand
        servers = {"<root>": mcp_json}

    result.servers_scanned = len(servers)

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue

        command = str(server_cfg.get("command") or "").strip().lower()
        args: list[Any] = server_cfg.get("args") or []

        if command == "npx":
            if _has_auto_install_flag(args):
                result.findings.append(
                    SupplyChainFinding(
                        server_name=server_name,
                        command=command,
                        args=list(args),
                        risk="auto_install",
                        severity="HIGH",
                        detail=(
                            f"Server '{server_name}' uses 'npx -y' which silently "
                            "installs arbitrary packages without user confirmation."
                        ),
                    )
                )
            check = _check_npm_args(args)
            if check:
                risk, detail = check
                severity = "HIGH" if risk == "unpinned_version" else "MEDIUM"
                result.findings.append(
                    SupplyChainFinding(
                        server_name=server_name,
                        command=command,
                        args=list(args),
                        risk=risk,
                        severity=severity,
                        detail=detail,
                    )
                )

        elif command == "uvx":
            check = _check_uvx_args(args)
            if check:
                risk, detail = check
                severity = "HIGH" if risk == "unpinned_version" else "MEDIUM"
                result.findings.append(
                    SupplyChainFinding(
                        server_name=server_name,
                        command=command,
                        args=list(args),
                        risk=risk,
                        severity=severity,
                        detail=detail,
                    )
                )

    result.clean = result.high_count == 0
    return result
