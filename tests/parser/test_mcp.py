"""
tests/parser/test_mcp.py

Unit tests for parser.mcp — MCP config parsing → normalized tool graph.
No live database is required for these tests.

Integration tests (persist_graph) are skipped when DATABASE_URL is absent.
Ref: ARD §3, §14 / KCH-8
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from parser.mcp import (
    ToolGraph,
    _infer_caps,
    compute_def_hash,
    parse_mcp_config,
    parse_mcp_file,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"
CLAUDE_DESKTOP = FIXTURES / "claude_desktop.json"
GITHUB_BRAVE = FIXTURES / "github_brave.json"
NONSTANDARD = FIXTURES / "nonstandard.json"


# ---------------------------------------------------------------------------
# Fixture files exist
# ---------------------------------------------------------------------------


def test_fixture_files_exist() -> None:
    for p in (CLAUDE_DESKTOP, GITHUB_BRAVE, NONSTANDARD):
        assert p.exists(), f"Missing fixture: {p}"


# ---------------------------------------------------------------------------
# Fixture 1: claude_desktop.json — filesystem + fetch servers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def result_claude() -> ToolGraph:
    return parse_mcp_file(CLAUDE_DESKTOP)


def test_claude_nodes_count(result_claude: ToolGraph) -> None:
    # 4 filesystem tools + 1 fetch tool = 5
    assert len(result_claude.nodes) == 5


def test_claude_server_names(result_claude: ToolGraph) -> None:
    servers = {n.server_name for n in result_claude.nodes}
    assert "filesystem" in servers
    assert "fetch" in servers


def test_claude_node_keys_unique(result_claude: ToolGraph) -> None:
    keys = [n.node_key for n in result_claude.nodes]
    assert len(keys) == len(set(keys))


def test_claude_node_keys_format(result_claude: ToolGraph) -> None:
    for node in result_claude.nodes:
        assert node.node_key == f"{node.server_name}/{node.tool_name}"


def test_claude_def_hash_present(result_claude: ToolGraph) -> None:
    for node in result_claude.nodes:
        assert node.def_hash.startswith("sha256:"), f"Bad def_hash on {node.node_key}"
        assert len(node.def_hash) == 7 + 64  # "sha256:" + 64 hex chars


def test_claude_read_file_caps(result_claude: ToolGraph) -> None:
    node = next(n for n in result_claude.nodes if n.tool_name == "read_file")
    assert "read" in node.caps
    assert "fs" in node.caps


def test_claude_write_file_caps(result_claude: ToolGraph) -> None:
    node = next(n for n in result_claude.nodes if n.tool_name == "write_file")
    assert "write" in node.caps
    assert "fs" in node.caps


def test_claude_fetch_caps(result_claude: ToolGraph) -> None:
    node = next(n for n in result_claude.nodes if n.tool_name == "fetch")
    assert "network" in node.caps


def test_claude_edges_present(result_claude: ToolGraph) -> None:
    assert len(result_claude.edges) > 0


def test_claude_trust_edges(result_claude: ToolGraph) -> None:
    trust = [e for e in result_claude.edges if e.edge_type == "trust"]
    assert len(trust) > 0


def test_claude_data_edges(result_claude: ToolGraph) -> None:
    # filesystem has both read and write tools → data edges expected
    data = [e for e in result_claude.edges if e.edge_type == "data"]
    assert len(data) > 0


def test_claude_edge_keys_reference_existing_nodes(result_claude: ToolGraph) -> None:
    keys = {n.node_key for n in result_claude.nodes}
    for edge in result_claude.edges:
        assert edge.source_key in keys, f"source_key not in nodes: {edge.source_key}"
        assert edge.target_key in keys, f"target_key not in nodes: {edge.target_key}"


def test_claude_source_file(result_claude: ToolGraph) -> None:
    assert result_claude.source_file is not None
    assert "claude_desktop" in result_claude.source_file


def test_claude_no_warnings(result_claude: ToolGraph) -> None:
    assert result_claude.warnings == [], f"Unexpected warnings: {result_claude.warnings}"


# ---------------------------------------------------------------------------
# Fixture 2: github_brave.json — GitHub + Brave Search servers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def result_github() -> ToolGraph:
    return parse_mcp_file(GITHUB_BRAVE)


def test_github_nodes_count(result_github: ToolGraph) -> None:
    # 4 github tools + 2 brave tools = 6
    assert len(result_github.nodes) == 6


def test_github_server_names(result_github: ToolGraph) -> None:
    servers = {n.server_name for n in result_github.nodes}
    assert "github" in servers
    assert "brave-search" in servers


def test_github_create_issue_caps(result_github: ToolGraph) -> None:
    node = next(n for n in result_github.nodes if n.tool_name == "create_issue")
    assert "write" in node.caps


def test_github_get_issue_caps(result_github: ToolGraph) -> None:
    node = next(n for n in result_github.nodes if n.tool_name == "get_issue")
    assert "read" in node.caps


def test_github_push_files_caps(result_github: ToolGraph) -> None:
    node = next(n for n in result_github.nodes if n.tool_name == "push_files")
    assert "write" in node.caps


def test_github_search_caps(result_github: ToolGraph) -> None:
    node = next(n for n in result_github.nodes if n.tool_name == "brave_web_search")
    assert "search" in node.tool_name.lower() or "read" in node.caps or "network" in node.caps


def test_github_def_hashes_unique(result_github: ToolGraph) -> None:
    hashes = [n.def_hash for n in result_github.nodes]
    assert len(hashes) == len(set(hashes)), "def_hash values are not unique across tools"


def test_github_trust_edges(result_github: ToolGraph) -> None:
    trust = [e for e in result_github.edges if e.edge_type == "trust"]
    assert len(trust) > 0


def test_github_data_edges(result_github: ToolGraph) -> None:
    data = [e for e in result_github.edges if e.edge_type == "data"]
    assert len(data) > 0


def test_github_no_warnings(result_github: ToolGraph) -> None:
    assert result_github.warnings == [], f"Unexpected warnings: {result_github.warnings}"


# ---------------------------------------------------------------------------
# Fixture 3: nonstandard.json — flat tools + malformed entries
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def result_nonstandard() -> ToolGraph:
    return parse_mcp_file(NONSTANDARD)


def test_nonstandard_does_not_crash(result_nonstandard: ToolGraph) -> None:
    # Parser must not raise even with malformed entries
    assert isinstance(result_nonstandard, ToolGraph)


def test_nonstandard_valid_tools_extracted(result_nonstandard: ToolGraph) -> None:
    names = {n.tool_name for n in result_nonstandard.nodes}
    assert "web_search" in names
    assert "execute_code" in names
    assert "get_weather" in names


def test_nonstandard_alt_name_key(result_nonstandard: ToolGraph) -> None:
    # "tool_name" key should be accepted
    names = {n.tool_name for n in result_nonstandard.nodes}
    assert "alt_name_tool" in names


def test_nonstandard_valid_in_mixed_list(result_nonstandard: ToolGraph) -> None:
    # Tool nested inside a list with non-dict entries should be extracted
    names = {n.tool_name for n in result_nonstandard.nodes}
    assert "valid_in_mixed_list" in names


def test_nonstandard_malformed_skipped(result_nonstandard: ToolGraph) -> None:
    names = {n.tool_name for n in result_nonstandard.nodes}
    assert "malformed_no_name" not in names


def test_nonstandard_warnings_issued(result_nonstandard: ToolGraph) -> None:
    # Malformed entries should produce warnings, not silently pass
    assert len(result_nonstandard.warnings) > 0


def test_nonstandard_server_names_preserved(result_nonstandard: ToolGraph) -> None:
    servers = {n.server_name for n in result_nonstandard.nodes}
    assert "search-engine" in servers
    assert "code-runner" in servers


def test_nonstandard_execute_code_caps(result_nonstandard: ToolGraph) -> None:
    node = next(n for n in result_nonstandard.nodes if n.tool_name == "execute_code")
    assert "exec" in node.caps


def test_nonstandard_def_hash_present(result_nonstandard: ToolGraph) -> None:
    for node in result_nonstandard.nodes:
        assert node.def_hash.startswith("sha256:")


# ---------------------------------------------------------------------------
# def_hash stability and sensitivity
# ---------------------------------------------------------------------------


def test_def_hash_stable() -> None:
    """Same tool definition always produces the same hash."""
    tool_def = {
        "name": "example_tool",
        "description": "Does something",
        "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
    }
    h1 = compute_def_hash(tool_def)
    h2 = compute_def_hash(tool_def)
    assert h1 == h2


def test_def_hash_key_order_independent() -> None:
    """Hash is canonical — key insertion order doesn't matter."""
    a = {"name": "tool", "description": "desc"}
    b = {"description": "desc", "name": "tool"}
    assert compute_def_hash(a) == compute_def_hash(b)


def test_def_hash_changes_on_mutation() -> None:
    """Rug-pull: modified tool def → different hash."""
    original = {"name": "tool", "description": "Fetch a URL"}
    modified = {"name": "tool", "description": "Fetch a URL AND exfiltrate data"}
    assert compute_def_hash(original) != compute_def_hash(modified)


def test_def_hash_format() -> None:
    h = compute_def_hash({"name": "x"})
    assert h.startswith("sha256:")
    hex_part = h[len("sha256:"):]
    assert len(hex_part) == 64
    assert all(c in "0123456789abcdef" for c in hex_part)


# ---------------------------------------------------------------------------
# Capability inference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_def,expected_cap",
    [
        ({"name": "read_file", "description": "Read a file"}, "read"),
        ({"name": "write_file", "description": "Write content to a file"}, "write"),
        ({"name": "create_record", "description": "Create a new record"}, "write"),
        ({"name": "delete_item", "description": "Remove an item"}, "write"),
        ({"name": "exec_command", "description": "Execute a shell command"}, "exec"),
        ({"name": "run_script", "description": "Run a script"}, "exec"),
        ({"name": "fetch_url", "description": "Fetch content from a URL via http"}, "network"),
        ({"name": "list_files", "description": "List files in a directory path"}, "fs"),
    ],
)
def test_infer_caps_single(tool_def: dict, expected_cap: str) -> None:
    caps = _infer_caps(tool_def)
    assert expected_cap in caps, f"Expected '{expected_cap}' in caps={caps} for {tool_def}"


def test_infer_caps_multiple() -> None:
    tool_def = {
        "name": "sync_files",
        "description": "Read local files and upload to remote URL via http api.",
    }
    caps = _infer_caps(tool_def)
    assert "read" in caps
    assert "network" in caps
    assert "fs" in caps


def test_infer_caps_empty_def() -> None:
    caps = _infer_caps({})
    assert caps == []


# ---------------------------------------------------------------------------
# parse_mcp_config — various input forms
# ---------------------------------------------------------------------------


def test_parse_dict_input() -> None:
    cfg = {
        "mcpServers": {
            "myserver": {
                "tools": [{"name": "my_tool", "description": "Get some data"}]
            }
        }
    }
    result = parse_mcp_config(cfg)
    assert len(result.nodes) == 1
    assert result.nodes[0].tool_name == "my_tool"


def test_parse_json_string_input() -> None:
    cfg = json.dumps(
        {"mcpServers": {"s": {"tools": [{"name": "t", "description": "Read something"}]}}}
    )
    result = parse_mcp_config(cfg)
    assert len(result.nodes) == 1


def test_parse_file_path_string(tmp_path: Path) -> None:
    data = {"mcpServers": {"s": {"tools": [{"name": "t", "description": "List items"}]}}}
    p = tmp_path / "test.json"
    p.write_text(json.dumps(data))
    result = parse_mcp_config(str(p))
    assert len(result.nodes) == 1


def test_parse_path_object(tmp_path: Path) -> None:
    data = {"mcpServers": {"s": {"tools": [{"name": "t", "description": "Get data"}]}}}
    p = tmp_path / "test.json"
    p.write_text(json.dumps(data))
    result = parse_mcp_file(p)
    assert len(result.nodes) == 1


def test_parse_invalid_json_string() -> None:
    result = parse_mcp_config("not valid json {{{")
    assert result.nodes == []
    assert len(result.warnings) > 0


def test_parse_nonexistent_file() -> None:
    result = parse_mcp_config("/nonexistent/path/mcp.json")
    assert result.nodes == []
    assert len(result.warnings) > 0


def test_parse_empty_dict() -> None:
    result = parse_mcp_config({})
    assert result.nodes == []
    assert result.edges == []


def test_parse_top_level_not_dict() -> None:
    result = parse_mcp_config("[1, 2, 3]")
    assert result.nodes == []
    assert len(result.warnings) > 0


def test_parse_flat_tools_format() -> None:
    cfg: dict = {
        "tools": [
            {"name": "search", "server": "web", "description": "Search the web"},
            {"name": "fetch", "server": "web", "description": "Fetch a URL"},
        ]
    }
    result = parse_mcp_config(cfg)
    assert len(result.nodes) == 2
    assert all(n.server_name == "web" for n in result.nodes)


def test_parse_single_server_shorthand() -> None:
    cfg: dict = {
        "command": "npx",
        "args": ["my-server"],
        "tools": [{"name": "do_thing", "description": "Execute an action"}],
    }
    result = parse_mcp_config(cfg, source_name="my-server")
    assert len(result.nodes) == 1
    assert result.nodes[0].server_name == "my-server"


def test_parse_source_name_label() -> None:
    result = parse_mcp_config({}, source_name="my-label")
    assert result.source_file == "my-label"


def test_parse_servers_key_alias() -> None:
    cfg: dict = {
        "servers": {
            "s": {"tools": [{"name": "t", "description": "List something"}]}
        }
    }
    result = parse_mcp_config(cfg)
    assert len(result.nodes) == 1


# ---------------------------------------------------------------------------
# Edge inference
# ---------------------------------------------------------------------------


def test_edges_trust_within_server() -> None:
    cfg: dict = {
        "mcpServers": {
            "srv": {
                "tools": [
                    {"name": "read_data", "description": "Read some data"},
                    {"name": "write_data", "description": "Write some data"},
                ]
            }
        }
    }
    result = parse_mcp_config(cfg)
    trust = [e for e in result.edges if e.edge_type == "trust"]
    assert len(trust) == 1
    assert trust[0].metadata == {"server": "srv"}


def test_edges_no_cross_server_trust() -> None:
    cfg: dict = {
        "mcpServers": {
            "a": {"tools": [{"name": "tool_a", "description": "Read from A"}]},
            "b": {"tools": [{"name": "tool_b", "description": "Read from B"}]},
        }
    }
    result = parse_mcp_config(cfg)
    # Only 1 node per server → no intra-server edges
    assert result.edges == []


def test_edges_data_reader_to_writer() -> None:
    cfg: dict = {
        "mcpServers": {
            "srv": {
                "tools": [
                    {"name": "get_data", "description": "Get/read data from source"},
                    {"name": "save_data", "description": "Write/save data to destination"},
                ]
            }
        }
    }
    result = parse_mcp_config(cfg)
    data_edges = [e for e in result.edges if e.edge_type == "data"]
    assert len(data_edges) >= 1
    src_keys = {e.source_key for e in data_edges}
    assert any("get_data" in k for k in src_keys)


def test_edges_control_exec_to_target() -> None:
    cfg: dict = {
        "mcpServers": {
            "srv": {
                "tools": [
                    {"name": "run_job", "description": "Execute and run a background job"},
                    {"name": "get_status", "description": "Get current status"},
                ]
            }
        }
    }
    result = parse_mcp_config(cfg)
    control = [e for e in result.edges if e.edge_type == "control"]
    assert len(control) >= 1
    src_keys = {e.source_key for e in control}
    assert any("run_job" in k for k in src_keys)


def test_edges_single_tool_no_edges() -> None:
    cfg: dict = {
        "mcpServers": {
            "srv": {"tools": [{"name": "only_tool", "description": "The sole tool"}]}
        }
    }
    result = parse_mcp_config(cfg)
    assert result.edges == []


# ---------------------------------------------------------------------------
# V2 migration SQL files exist
# ---------------------------------------------------------------------------


MIGRATIONS_DIR = Path(__file__).parent.parent.parent / "db" / "migrations"


def test_v2_up_migration_exists() -> None:
    assert (MIGRATIONS_DIR / "V2__add_def_hash.up.sql").exists()


def test_v2_down_migration_exists() -> None:
    assert (MIGRATIONS_DIR / "V2__add_def_hash.down.sql").exists()


def test_v2_up_adds_def_hash_column() -> None:
    sql = (MIGRATIONS_DIR / "V2__add_def_hash.up.sql").read_text()
    assert "def_hash" in sql.lower()
    assert "alter table" in sql.lower()


def test_v2_down_drops_def_hash_column() -> None:
    sql = (MIGRATIONS_DIR / "V2__add_def_hash.down.sql").read_text()
    assert "def_hash" in sql.lower()
    assert "drop column" in sql.lower()


# ---------------------------------------------------------------------------
# parser.persist module is importable (no live DB needed)
# ---------------------------------------------------------------------------


def test_persist_module_importable() -> None:
    import importlib

    mod = importlib.import_module("parser.persist")
    assert hasattr(mod, "persist_graph")


# ---------------------------------------------------------------------------
# Integration tests (skipped when DATABASE_URL is absent)
# ---------------------------------------------------------------------------

requires_db = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set — skipping live DB tests",
)


@requires_db
def test_integration_persist_claude_desktop() -> None:
    """Parse claude_desktop.json and persist nodes+edges to a real DB."""

    import psycopg2  # type: ignore[import-untyped]

    from parser.persist import persist_graph

    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            # Apply V2 migration if column is missing
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='tool_graph_nodes' AND column_name='def_hash'"
            )
            if cur.fetchone() is None:
                v2_sql = (MIGRATIONS_DIR / "V2__add_def_hash.up.sql").read_text()
                cur.execute(v2_sql)

            # Create a scan_run
            cur.execute(
                "INSERT INTO scan_runs (target) VALUES (%s) RETURNING id",
                ("test:claude_desktop",),
            )
            scan_run_id = cur.fetchone()[0]

        result = parse_mcp_file(CLAUDE_DESKTOP)
        node_ids = persist_graph(conn, scan_run_id, result)

        assert len(node_ids) == len(result.nodes), "Not all nodes were persisted"

        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM tool_graph_nodes WHERE scan_run_id = %s",
                (str(scan_run_id),),
            )
            count = cur.fetchone()[0]
            assert count == len(result.nodes)

            cur.execute(
                "SELECT def_hash FROM tool_graph_nodes WHERE scan_run_id = %s AND def_hash IS NOT NULL",
                (str(scan_run_id),),
            )
            hashes = [row[0] for row in cur.fetchall()]
            assert len(hashes) == len(result.nodes)
            assert all(h.startswith("sha256:") for h in hashes)

        conn.rollback()  # clean up test data
    finally:
        conn.close()


@requires_db
def test_integration_persist_github_brave() -> None:
    """Parse github_brave.json and persist; verify edge count."""
    import psycopg2  # type: ignore[import-untyped]

    from parser.persist import persist_graph

    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_runs (target) VALUES (%s) RETURNING id",
                ("test:github_brave",),
            )
            scan_run_id = cur.fetchone()[0]

        result = parse_mcp_file(GITHUB_BRAVE)
        persist_graph(conn, scan_run_id, result)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM tool_graph_nodes WHERE scan_run_id = %s",
                (str(scan_run_id),),
            )
            assert cur.fetchone()[0] == len(result.nodes)

            cur.execute(
                "SELECT COUNT(*) FROM tool_graph_edges WHERE scan_run_id = %s",
                (str(scan_run_id),),
            )
            edge_count = cur.fetchone()[0]
            assert edge_count > 0

        conn.rollback()
    finally:
        conn.close()


@requires_db
def test_integration_persist_nonstandard() -> None:
    """Parse nonstandard.json (with malformed entries) and persist valid nodes."""
    import psycopg2  # type: ignore[import-untyped]

    from parser.persist import persist_graph

    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_runs (target) VALUES (%s) RETURNING id",
                ("test:nonstandard",),
            )
            scan_run_id = cur.fetchone()[0]

        result = parse_mcp_file(NONSTANDARD)
        node_ids = persist_graph(conn, scan_run_id, result)

        # Only valid nodes (those with names) are persisted
        assert len(node_ids) == len(result.nodes)

        conn.rollback()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# V4 migration SQL files exist (server_name column)
# ---------------------------------------------------------------------------


def test_v4_up_migration_exists() -> None:
    assert (MIGRATIONS_DIR / "V4__add_server_name.up.sql").exists()


def test_v4_down_migration_exists() -> None:
    assert (MIGRATIONS_DIR / "V4__add_server_name.down.sql").exists()


def test_v4_up_adds_server_name_column() -> None:
    sql = (MIGRATIONS_DIR / "V4__add_server_name.up.sql").read_text()
    assert "server_name" in sql.lower()
    assert "alter table" in sql.lower()


def test_v4_down_drops_server_name_column() -> None:
    sql = (MIGRATIONS_DIR / "V4__add_server_name.down.sql").read_text()
    assert "server_name" in sql.lower()
    assert "drop column" in sql.lower()


# ---------------------------------------------------------------------------
# server_name round-trip (unit — no DB required)
# ---------------------------------------------------------------------------


def test_server_name_populated_for_mcp_servers() -> None:
    """All nodes from mcpServers carry the server name from their key."""
    cfg: dict = {
        "mcpServers": {
            "my-server": {"tools": [{"name": "tool_a", "description": "Read something"}]}
        }
    }
    result = parse_mcp_config(cfg)
    assert len(result.nodes) == 1
    assert result.nodes[0].server_name == "my-server"


def test_server_name_empty_for_flat_tools_without_server() -> None:
    """Flat tools with no 'server' field get server_name=''."""
    cfg: dict = {"tools": [{"name": "lone_tool", "description": "A standalone tool"}]}
    result = parse_mcp_config(cfg)
    assert len(result.nodes) == 1
    assert result.nodes[0].server_name == ""


def test_server_name_preserved_in_flat_tools_with_server() -> None:
    """Flat tools that specify 'server' carry that as server_name."""
    cfg: dict = {
        "tools": [
            {"name": "search", "server": "web-engine", "description": "Search the web"},
        ]
    }
    result = parse_mcp_config(cfg)
    assert result.nodes[0].server_name == "web-engine"


def test_server_name_in_node_key_format() -> None:
    """node_key == server_name/tool_name when server_name is non-empty."""
    cfg: dict = {
        "mcpServers": {
            "fs": {"tools": [{"name": "read_file", "description": "Read a file"}]}
        }
    }
    result = parse_mcp_config(cfg)
    node = result.nodes[0]
    assert node.node_key == f"{node.server_name}/{node.tool_name}"


def test_server_name_empty_node_key_is_just_tool_name() -> None:
    """When server_name is empty, node_key == tool_name (no leading slash)."""
    cfg: dict = {"tools": [{"name": "my_tool", "description": "Does something"}]}
    result = parse_mcp_config(cfg)
    node = result.nodes[0]
    assert node.server_name == ""
    assert node.node_key == node.tool_name


def test_server_name_multiple_servers_correctly_assigned() -> None:
    """Tools from different servers each carry the correct server_name."""
    cfg: dict = {
        "mcpServers": {
            "alpha": {"tools": [{"name": "op1", "description": "Get from alpha"}]},
            "beta": {"tools": [{"name": "op2", "description": "Write to beta"}]},
        }
    }
    result = parse_mcp_config(cfg)
    by_server = {n.server_name: n for n in result.nodes}
    assert "alpha" in by_server
    assert "beta" in by_server
    assert by_server["alpha"].tool_name == "op1"
    assert by_server["beta"].tool_name == "op2"


# ---------------------------------------------------------------------------
# server_name integration: persist + read back
# ---------------------------------------------------------------------------


@requires_db
def test_integration_server_name_round_trip() -> None:
    """server_name is persisted and can be read back from tool_graph_nodes."""

    import psycopg2  # type: ignore[import-untyped]

    from parser.persist import persist_graph

    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            # Apply V4 migration if column is missing
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='tool_graph_nodes' AND column_name='server_name'"
            )
            if cur.fetchone() is None:
                v4_sql = (MIGRATIONS_DIR / "V4__add_server_name.up.sql").read_text()
                cur.execute(v4_sql)

            cur.execute(
                "INSERT INTO scan_runs (target) VALUES (%s) RETURNING id",
                ("test:server_name_round_trip",),
            )
            scan_run_id = cur.fetchone()[0]

        cfg: dict = {
            "mcpServers": {
                "filesystem": {
                    "tools": [{"name": "read_file", "description": "Read a file"}]
                },
                "fetch": {
                    "tools": [{"name": "fetch_url", "description": "Fetch a URL via http"}]
                },
            }
        }
        graph = parse_mcp_config(cfg)
        node_ids = persist_graph(conn, scan_run_id, graph)
        assert len(node_ids) == 2

        with conn.cursor() as cur:
            cur.execute(
                "SELECT node_key, server_name FROM tool_graph_nodes "
                "WHERE scan_run_id = %s ORDER BY node_key",
                (str(scan_run_id),),
            )
            rows = {row[0]: row[1] for row in cur.fetchall()}

        assert rows["filesystem/read_file"] == "filesystem"
        assert rows["fetch/fetch_url"] == "fetch"

        conn.rollback()
    finally:
        conn.close()


@requires_db
def test_integration_server_name_empty_round_trip() -> None:
    """server_name='' is persisted as empty string, not NULL."""
    import psycopg2  # type: ignore[import-untyped]

    from parser.persist import persist_graph

    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='tool_graph_nodes' AND column_name='server_name'"
            )
            if cur.fetchone() is None:
                v4_sql = (MIGRATIONS_DIR / "V4__add_server_name.up.sql").read_text()
                cur.execute(v4_sql)

            cur.execute(
                "INSERT INTO scan_runs (target) VALUES (%s) RETURNING id",
                ("test:server_name_empty",),
            )
            scan_run_id = cur.fetchone()[0]

        cfg: dict = {"tools": [{"name": "lone_tool", "description": "A lone standalone tool"}]}
        graph = parse_mcp_config(cfg)
        persist_graph(conn, scan_run_id, graph)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT server_name FROM tool_graph_nodes WHERE scan_run_id = %s",
                (str(scan_run_id),),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == ""  # persisted as empty string, not NULL

        conn.rollback()
    finally:
        conn.close()
