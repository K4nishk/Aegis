"""
parser/mcp.py — Parse mcp.json / tool definitions → normalized tool graph.

Supported MCP config formats:
  A. Claude Desktop:  {"mcpServers": {<name>: {command, args, tools?}}}
  B. Tool-inline:     {"mcpServers": {<name>: {tools: [...]}}}
  C. Flat tools list: {"tools": [...]}
  D. Single-server:   {"command": ..., "tools": [...]}

Tolerates missing / extra fields and nonstandard schemas (§16 open-Q).
Ref: ARD §3, §14 / KCH-8
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------


@dataclass
class ToolNode:
    """Represents one MCP tool as a graph node."""

    node_key: str  # Unique: "{server_name}/{tool_name}" or just "{tool_name}"
    tool_name: str
    server_name: str  # Empty string when there is no server context
    def_hash: str  # "sha256:<hex>" of the canonical (sorted-key) tool def
    tool_version: str | None = None
    caps: list[str] = field(default_factory=list)
    raw_def: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolEdge:
    """Directed relationship between two tool nodes."""

    source_key: str
    target_key: str
    edge_type: str  # "data" | "control" | "trust"
    metadata: dict[str, Any] | None = None


@dataclass
class ToolGraph:
    """A normalized tool graph produced by parse_mcp_config.

    Holds both the domain data (nodes + edges) and parse diagnostics
    (source_file, warnings) as a pragmatic single type.
    """

    nodes: list[ToolNode] = field(default_factory=list)
    edges: list[ToolEdge] = field(default_factory=list)
    source_file: str | None = None
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Capability inference
# ---------------------------------------------------------------------------

_READ_RE = re.compile(
    r"\b(read|get|list|fetch|search|find|query|view|show|describe|retrieve)\b", re.I
)
_WRITE_RE = re.compile(
    r"\b(write|create|update|delete|remove|put|post|set|add|insert|patch|push|commit)\b", re.I
)
_EXEC_RE = re.compile(
    r"\b(exec|run|spawn|execute|invoke|call|start|stop|kill|launch|trigger)\b", re.I
)
_NET_RE = re.compile(r"\b(http|https?|url|fetch|download|upload|webhook|api|request)\b", re.I)
_FS_RE = re.compile(r"\b(file|dir|path|folder|disk|filesystem|directory)\b", re.I)


def _infer_caps(tool_def: dict[str, Any]) -> list[str]:
    """Infer capability tags from a tool definition dict."""
    schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
    text = " ".join(
        filter(
            None,
            [
                str(tool_def.get("name", "")),
                str(tool_def.get("description", "")),
                json.dumps(schema),
            ],
        )
    )
    caps: set[str] = set()
    if _READ_RE.search(text):
        caps.add("read")
    if _WRITE_RE.search(text):
        caps.add("write")
    if _EXEC_RE.search(text):
        caps.add("exec")
    if _NET_RE.search(text):
        caps.add("network")
    if _FS_RE.search(text):
        caps.add("fs")
    return sorted(caps)


# ---------------------------------------------------------------------------
# def_hash
# ---------------------------------------------------------------------------


def compute_def_hash(tool_def: dict[str, Any]) -> str:
    """Return 'sha256:<hex>' of the canonical (sorted-key) JSON of tool_def."""
    canonical = json.dumps(tool_def, sort_keys=True, ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Tool extraction helpers
# ---------------------------------------------------------------------------


def _coerce_tool_name(raw: dict[str, Any]) -> str | None:
    """Return a non-empty tool name from various key spellings, or None."""
    for key in ("name", "tool_name", "id", "tool_id"):
        val = raw.get(key)
        if val and isinstance(val, str):
            return val.strip()
    return None


def _extract_tools_from_server(
    server_name: str,
    server_cfg: Any,
) -> tuple[list[ToolNode], list[str]]:
    """Extract ToolNodes from one server config entry."""
    nodes: list[ToolNode] = []
    warnings: list[str] = []

    if not isinstance(server_cfg, dict):
        warnings.append(
            f"Server '{server_name}': config is not a dict "
            f"(got {type(server_cfg).__name__}), skipping"
        )
        return nodes, warnings

    raw_tools = server_cfg.get("tools") or server_cfg.get("tool_list") or []
    if not isinstance(raw_tools, list):
        warnings.append(
            f"Server '{server_name}': 'tools' field is not a list "
            f"(got {type(raw_tools).__name__}), ignoring"
        )
        raw_tools = []

    for raw in raw_tools:
        if not isinstance(raw, dict):
            warnings.append(f"Server '{server_name}': tool entry is not a dict, skipping")
            continue
        tool_name = _coerce_tool_name(raw)
        if not tool_name:
            warnings.append(f"Server '{server_name}': tool entry missing name, skipping")
            continue
        nodes.append(
            ToolNode(
                node_key=f"{server_name}/{tool_name}",
                tool_name=tool_name,
                server_name=server_name,
                def_hash=compute_def_hash(raw),
                tool_version=raw.get("version") or raw.get("tool_version"),
                caps=_infer_caps(raw),
                raw_def=dict(raw),
            )
        )

    return nodes, warnings


def _extract_flat_tools(raw_tools: Any, warnings: list[str]) -> list[ToolNode]:
    """Extract ToolNodes from a top-level 'tools' list."""
    nodes: list[ToolNode] = []
    if not isinstance(raw_tools, list):
        warnings.append(
            f"Top-level 'tools' is not a list (got {type(raw_tools).__name__}), ignoring"
        )
        return nodes

    for raw in raw_tools:
        if not isinstance(raw, dict):
            warnings.append("Flat tool entry is not a dict, skipping")
            continue
        tool_name = _coerce_tool_name(raw)
        if not tool_name:
            warnings.append("Flat tool entry missing name, skipping")
            continue
        server_name = raw.get("server") or raw.get("server_name") or ""
        if not isinstance(server_name, str):
            server_name = str(server_name)
        node_key = f"{server_name}/{tool_name}" if server_name else tool_name
        nodes.append(
            ToolNode(
                node_key=node_key,
                tool_name=tool_name,
                server_name=server_name,
                def_hash=compute_def_hash(raw),
                tool_version=raw.get("version") or raw.get("tool_version"),
                caps=_infer_caps(raw),
                raw_def=dict(raw),
            )
        )
    return nodes


# ---------------------------------------------------------------------------
# Edge inference
# ---------------------------------------------------------------------------


def _infer_edges(nodes: list[ToolNode]) -> list[ToolEdge]:
    """Infer edges between nodes via capability heuristics.

    Edge types produced:
    - trust:   all tool pairs within the same server (co-located → mutual trust)
    - data:    reader tools → writer tools within the same server
    - control: exec-capable tools → non-exec tools within the same server
    """
    edges: list[ToolEdge] = []

    by_server: dict[str, list[ToolNode]] = {}
    for node in nodes:
        by_server.setdefault(node.server_name, []).append(node)

    for server_name, snodes in by_server.items():
        if len(snodes) < 2:
            continue

        # Trust edges: every pair within the same server
        for i, src in enumerate(snodes):
            for dst in snodes[i + 1 :]:
                edges.append(
                    ToolEdge(
                        source_key=src.node_key,
                        target_key=dst.node_key,
                        edge_type="trust",
                        metadata={"server": server_name} if server_name else None,
                    )
                )

        # Data edges: reader tools → writer tools
        readers = [n for n in snodes if "read" in n.caps]
        writers = [n for n in snodes if "write" in n.caps]
        for r in readers:
            for w in writers:
                if r.node_key != w.node_key:
                    edges.append(
                        ToolEdge(
                            source_key=r.node_key,
                            target_key=w.node_key,
                            edge_type="data",
                            metadata={"inferred": "read→write"},
                        )
                    )

        # Control edges: exec tools → non-exec tools
        execs = [n for n in snodes if "exec" in n.caps]
        non_execs = [n for n in snodes if "exec" not in n.caps]
        for e in execs:
            for t in non_execs:
                edges.append(
                    ToolEdge(
                        source_key=e.node_key,
                        target_key=t.node_key,
                        edge_type="control",
                        metadata={"inferred": "exec→target"},
                    )
                )

    return edges


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def parse_mcp_config(
    source: str | Path | dict[str, Any],
    *,
    source_name: str | None = None,
) -> ToolGraph:
    """Parse an MCP config into a normalized tool graph.

    Args:
        source: File path (str or Path), raw JSON string, or pre-parsed dict.
        source_name: Label for ToolGraph.source_file and warning messages.

    Returns:
        ToolGraph containing nodes, edges, and any parse warnings.
    """
    result = ToolGraph()
    warnings = result.warnings

    # --- Resolve to raw dict ---
    raw: Any
    if isinstance(source, dict):
        raw = source
        result.source_file = source_name
    elif isinstance(source, Path):
        result.source_file = source_name or str(source)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"Cannot load {source}: {exc}")
            return result
    else:  # str — may be a file path or raw JSON
        p = Path(source)
        if p.exists():
            result.source_file = source_name or str(p)
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                warnings.append(f"Cannot load {p}: {exc}")
                return result
        else:
            result.source_file = source_name
            try:
                raw = json.loads(source)
            except json.JSONDecodeError as exc:
                warnings.append(f"Cannot parse JSON string: {exc}")
                return result

    if not isinstance(raw, dict):
        warnings.append(f"Top-level JSON value is not an object (got {type(raw).__name__})")
        return result

    nodes: list[ToolNode] = []

    # Format A/B: {"mcpServers": {<name>: {...}}} — also accept "servers"
    mcp_servers = raw.get("mcpServers") or raw.get("mcp_servers") or raw.get("servers")
    if isinstance(mcp_servers, dict):
        for srv_name, srv_cfg in mcp_servers.items():
            srv_nodes, srv_warnings = _extract_tools_from_server(str(srv_name), srv_cfg)
            nodes.extend(srv_nodes)
            warnings.extend(srv_warnings)
    elif mcp_servers is not None:
        warnings.append(
            f"'mcpServers' / 'servers' is not a dict (got {type(mcp_servers).__name__}), ignoring"
        )

    # Format D: single-server shorthand {"command": ..., "tools": [...]}
    # Must be checked before Format C so the "tools" key is treated as server-level
    # tools rather than a flat list.
    if not nodes and "command" in raw:
        fallback_name = source_name or "default"
        srv_nodes, srv_warnings = _extract_tools_from_server(fallback_name, raw)
        nodes.extend(srv_nodes)
        warnings.extend(srv_warnings)

    # Format C: top-level {"tools": [...]} — only when no "command" shorthand detected
    if "command" not in raw:
        top_tools = raw.get("tools")
        if top_tools is not None:
            existing_keys = {n.node_key for n in nodes}
            flat = _extract_flat_tools(top_tools, warnings)
            nodes.extend(n for n in flat if n.node_key not in existing_keys)

    result.nodes = nodes
    result.edges = _infer_edges(nodes)
    return result


def parse_mcp_file(path: str | Path) -> ToolGraph:
    """Convenience wrapper: parse a JSON file at path."""
    return parse_mcp_config(Path(path))
