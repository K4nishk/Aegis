"""
parser/persist.py — Persist parsed tool graph nodes and edges to Postgres.

Requires psycopg2 and the schema from KCH-6 (V1) extended by KCH-8 (V2,
which adds the def_hash column to tool_graph_nodes).

Usage::

    import psycopg2
    from parser.mcp import parse_mcp_file
    from parser.persist import persist_graph

    conn = psycopg2.connect(dsn)
    result = parse_mcp_file("mcp.json")
    try:
        node_ids = persist_graph(conn, scan_run_id, result)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from parser.mcp import ToolGraph

# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_INSERT_NODE = """
    INSERT INTO tool_graph_nodes
        (scan_run_id, node_key, tool_name, server_name, tool_version, caps, def_hash)
    VALUES
        (%(scan_run_id)s, %(node_key)s, %(tool_name)s,
         %(server_name)s, %(tool_version)s, %(caps)s::jsonb, %(def_hash)s)
    ON CONFLICT (scan_run_id, node_key) DO UPDATE
        SET server_name  = EXCLUDED.server_name,
            tool_version = EXCLUDED.tool_version,
            caps         = EXCLUDED.caps,
            def_hash     = EXCLUDED.def_hash
    RETURNING id
"""

_INSERT_EDGE = """
    INSERT INTO tool_graph_edges
        (scan_run_id, source_node_id, target_node_id, edge_type, metadata)
    VALUES
        (%(scan_run_id)s, %(source_node_id)s, %(target_node_id)s,
         %(edge_type)s, %(metadata)s::jsonb)
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def persist_graph(
    conn: Any,
    scan_run_id: str | UUID,
    result: ToolGraph,
) -> dict[str, str]:
    """Persist ToolGraph to the database within the caller's transaction.

    Args:
        conn: Active psycopg2 connection (caller manages commit/rollback).
        scan_run_id: UUID of the parent scan_run row.
        result: Parsed tool graph from parse_mcp_config / parse_mcp_file.

    Returns:
        Mapping {node_key: db_uuid_str} for all inserted / upserted nodes.
    """
    node_ids: dict[str, str] = {}
    scan_id = str(scan_run_id)

    with conn.cursor() as cur:
        for node in result.nodes:
            cur.execute(
                _INSERT_NODE,
                {
                    "scan_run_id": scan_id,
                    "node_key": node.node_key,
                    "tool_name": node.tool_name,
                    "server_name": node.server_name,
                    "tool_version": node.tool_version,
                    "caps": json.dumps(node.caps),
                    "def_hash": node.def_hash,
                },
            )
            row = cur.fetchone()
            if row:
                node_ids[node.node_key] = str(row[0])

        for edge in result.edges:
            src_id = node_ids.get(edge.source_key)
            dst_id = node_ids.get(edge.target_key)
            if not src_id or not dst_id:
                continue
            cur.execute(
                _INSERT_EDGE,
                {
                    "scan_run_id": scan_id,
                    "source_node_id": src_id,
                    "target_node_id": dst_id,
                    "edge_type": edge.edge_type,
                    "metadata": json.dumps(edge.metadata) if edge.metadata is not None else "null",
                },
            )

    return node_ids
