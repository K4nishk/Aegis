"""
tests/analyzer/test_trifecta.py

Unit tests for analyzer.trifecta — security cap tagging and trifecta path detection.
No live database required.

Ref: ARD §0 thesis, §14 trifecta rule / KCH-9
"""

from __future__ import annotations

from pathlib import Path

import pytest

from analyzer.trifecta import (
    CapTag,
    SecurityProfile,
    TrifectaResult,
    analyze_trifecta,
    tag_tool,
)
from parser.mcp import ToolNode, parse_mcp_config, parse_mcp_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"
TRIFECTA_GOLD = FIXTURES / "trifecta_gold.json"
MIGRATIONS_DIR = Path(__file__).parent.parent.parent / "db" / "migrations"


# ---------------------------------------------------------------------------
# CapTag unit tests
# ---------------------------------------------------------------------------


def test_cap_tag_true_is_risk_present() -> None:
    tag = CapTag("reads_private_data", True, 0.9)
    assert tag.is_risk_present() is True


def test_cap_tag_false_is_not_risk_present() -> None:
    tag = CapTag("reads_private_data", False, 0.8)
    assert tag.is_risk_present() is False


def test_cap_tag_unknown_is_risk_present() -> None:
    """Fail-safe: unknown must be treated as risk-present."""
    tag = CapTag("sees_untrusted_content", "unknown", 0.4)
    assert tag.is_risk_present() is True


# ---------------------------------------------------------------------------
# tag_tool — reads_private_data
# ---------------------------------------------------------------------------


def _make_node(
    tool_name: str,
    description: str,
    caps: list[str] | None = None,
    server: str = "srv",
) -> ToolNode:
    raw = {"name": tool_name, "description": description}
    return ToolNode(
        node_key=f"{server}/{tool_name}",
        tool_name=tool_name,
        server_name=server,
        def_hash="sha256:" + "0" * 64,
        caps=caps or [],
        raw_def=raw,
    )


@pytest.mark.parametrize(
    "description,expected_value",
    [
        ("Retrieve private credentials from vault.", True),
        ("Get secret tokens for service authentication.", True),
        ("Read API key and password for user.", True),
        ("List items in a queue.", False),
    ],
)
def test_tag_tool_reads_private_data_keyword(description: str, expected_value: bool) -> None:
    node = _make_node("tool", description, caps=["read"])
    profile = tag_tool(node)
    assert profile.reads_private_data.value is expected_value


def test_tag_tool_rpd_fs_read_is_unknown() -> None:
    """read + fs caps with no private keywords → unknown (fail-safe)."""
    node = _make_node("read_logs", "Read log entries from disk.", caps=["read", "fs"])
    profile = tag_tool(node)
    assert profile.reads_private_data.value == "unknown"


def test_tag_tool_rpd_evidence_populated_on_keyword_match() -> None:
    node = _make_node("get_secret", "Get the secret key.", caps=["read"])
    profile = tag_tool(node)
    assert profile.reads_private_data.value is True
    assert len(profile.reads_private_data.evidence) > 0
    assert any("keyword" in e for e in profile.reads_private_data.evidence)


# ---------------------------------------------------------------------------
# tag_tool — sees_untrusted_content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "description,expected_value",
    [
        ("Fetch a URL and return HTML webpage content.", True),
        ("Scrape a webpage for structured data.", True),
        ("Browse the web and return the page content.", True),
        ("Read a local configuration file.", False),
    ],
)
def test_tag_tool_sees_untrusted_content_keyword(description: str, expected_value: bool) -> None:
    node = _make_node("tool", description, caps=["read", "network"] if expected_value else ["read"])
    profile = tag_tool(node)
    assert profile.sees_untrusted_content.value is expected_value


def test_tag_tool_suc_network_cap_alone_is_unknown() -> None:
    """network cap without web/url/html keywords → unknown (may fetch external content)."""
    node = _make_node("api_call", "Make an API request.", caps=["network"])
    profile = tag_tool(node)
    # "api" doesn't match _SUD_RE; network cap alone → unknown
    assert profile.sees_untrusted_content.value == "unknown"


# ---------------------------------------------------------------------------
# tag_tool — can_exfiltrate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "description,expected_value",
    [
        ("Send and transmit data to an external webhook endpoint.", True),
        ("Publish a notification to the messaging service.", True),
        ("Upload files to remote storage.", True),
        ("Read data from a local cache.", False),
    ],
)
def test_tag_tool_can_exfiltrate_keyword(description: str, expected_value: bool) -> None:
    node = _make_node("tool", description, caps=["network"] if expected_value else [])
    profile = tag_tool(node)
    assert profile.can_exfiltrate.value is expected_value


def test_tag_tool_exf_network_write_is_true() -> None:
    """network + write caps → can_exfiltrate=True (medium confidence)."""
    node = _make_node("push_data", "Write data to remote endpoint.", caps=["network", "write"])
    profile = tag_tool(node)
    assert profile.can_exfiltrate.value is True
    assert profile.can_exfiltrate.confidence >= 0.7


def test_tag_tool_exf_exec_alone_is_unknown() -> None:
    """exec cap alone → unknown (spawned processes may exfiltrate)."""
    node = _make_node("run_cmd", "Execute a shell command.", caps=["exec"])
    profile = tag_tool(node)
    assert profile.can_exfiltrate.value == "unknown"


# ---------------------------------------------------------------------------
# SecurityProfile helpers
# ---------------------------------------------------------------------------


def test_security_profile_is_ambiguous_when_any_unknown() -> None:
    profile = SecurityProfile(
        node_key="srv/tool",
        reads_private_data=CapTag("reads_private_data", True, 0.9),
        sees_untrusted_content=CapTag("sees_untrusted_content", "unknown", 0.4),
        can_exfiltrate=CapTag("can_exfiltrate", False, 0.8),
    )
    assert profile.is_ambiguous() is True


def test_security_profile_not_ambiguous_when_all_definite() -> None:
    profile = SecurityProfile(
        node_key="srv/tool",
        reads_private_data=CapTag("reads_private_data", True, 0.9),
        sees_untrusted_content=CapTag("sees_untrusted_content", True, 0.9),
        can_exfiltrate=CapTag("can_exfiltrate", False, 0.8),
    )
    assert profile.is_ambiguous() is False


def test_security_profile_as_dict_structure() -> None:
    profile = SecurityProfile(
        node_key="srv/tool",
        reads_private_data=CapTag("reads_private_data", True, 0.9, ["keyword match: secret"]),
        sees_untrusted_content=CapTag("sees_untrusted_content", "unknown", 0.4),
        can_exfiltrate=CapTag("can_exfiltrate", False, 0.8),
    )
    d = profile.as_dict()
    assert set(d.keys()) == {"reads_private_data", "sees_untrusted_content", "can_exfiltrate"}
    assert d["reads_private_data"]["value"] is True
    assert d["sees_untrusted_content"]["value"] == "unknown"
    assert d["can_exfiltrate"]["value"] is False
    assert isinstance(d["reads_private_data"]["evidence"], list)


# ---------------------------------------------------------------------------
# Gold-set fixture — trifecta detection
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def gold_result() -> TrifectaResult:
    mcp = parse_mcp_file(TRIFECTA_GOLD)
    return analyze_trifecta(mcp)


def test_gold_fixture_exists() -> None:
    assert TRIFECTA_GOLD.exists(), f"Missing fixture: {TRIFECTA_GOLD}"


def test_gold_trifecta_detected(gold_result: TrifectaResult) -> None:
    """AC: flags seeded trifecta on gold set."""
    assert len(gold_result.findings) >= 1, "Expected ≥1 trifecta finding on gold set"


def test_gold_trifecta_path_is_ordered(gold_result: TrifectaResult) -> None:
    finding = gold_result.findings[0]
    assert isinstance(finding.path, list)
    assert len(finding.path) >= 1


def test_gold_trifecta_cap_nodes_in_path(gold_result: TrifectaResult) -> None:
    """All three cap-representative nodes must appear in the ordered path."""
    finding = gold_result.findings[0]
    assert finding.rpd_node in finding.path
    assert finding.suc_node in finding.path
    assert finding.exf_node in finding.path


def test_gold_trifecta_rpd_node_is_get_credentials(gold_result: TrifectaResult) -> None:
    finding = gold_result.findings[0]
    assert "get_credentials" in finding.rpd_node


def test_gold_trifecta_suc_node_is_browse_web(gold_result: TrifectaResult) -> None:
    finding = gold_result.findings[0]
    assert "browse_web" in finding.suc_node


def test_gold_trifecta_exf_node_is_post_to_webhook(gold_result: TrifectaResult) -> None:
    finding = gold_result.findings[0]
    assert "post_to_webhook" in finding.exf_node


def test_gold_trifecta_confidence_positive(gold_result: TrifectaResult) -> None:
    assert gold_result.findings[0].confidence > 0.0


def test_gold_ambiguity_rate_reported(gold_result: TrifectaResult) -> None:
    """Ambiguity rate must be a float in [0, 1] and be reported."""
    assert isinstance(gold_result.ambiguity_rate, float)
    assert 0.0 <= gold_result.ambiguity_rate <= 1.0


def test_gold_profiles_cover_all_nodes(gold_result: TrifectaResult) -> None:
    mcp = parse_mcp_file(TRIFECTA_GOLD)
    assert set(gold_result.profiles.keys()) == {n.node_key for n in mcp.nodes}


# ---------------------------------------------------------------------------
# analyze_trifecta — no-trifecta cases
# ---------------------------------------------------------------------------


def test_no_trifecta_single_cap_only() -> None:
    """A tool with only one cap cannot form a trifecta."""
    cfg = {
        "mcpServers": {
            "srv": {
                "tools": [
                    {"name": "read_file", "description": "Read a file."},
                    {"name": "list_dir", "description": "List directory contents."},
                ]
            }
        }
    }
    result = analyze_trifecta(parse_mcp_config(cfg))
    assert result.findings == []


def test_no_trifecta_disconnected_components() -> None:
    """Three tools in separate servers are not connected → no trifecta path."""
    cfg = {
        "mcpServers": {
            "vault": {
                "tools": [
                    {
                        "name": "get_secret",
                        "description": "Get private secret credentials.",
                    }
                ]
            },
            "browser": {
                "tools": [
                    {
                        "name": "browse_url",
                        "description": "Browse a URL webpage HTML.",
                    }
                ]
            },
            "notifier": {
                "tools": [
                    {
                        "name": "send_data",
                        "description": "Send and transmit data via webhook.",
                    }
                ]
            },
        }
    }
    result = analyze_trifecta(parse_mcp_config(cfg))
    # Each server has exactly 1 tool → no edges → 3 disconnected components,
    # each missing 2 of the 3 required caps.
    assert result.findings == []


def test_trifecta_single_node_all_three_caps() -> None:
    """A single tool with all three risk-present caps is a trivial trifecta."""
    cfg = {
        "mcpServers": {
            "all_in_one": {
                "tools": [
                    {
                        "name": "super_tool",
                        "description": (
                            "Retrieve private credentials from vault, "
                            "browse a URL webpage, and send via webhook."
                        ),
                    }
                ]
            }
        }
    }
    result = analyze_trifecta(parse_mcp_config(cfg))
    assert len(result.findings) >= 1
    # Path is the single node
    assert result.findings[0].path == ["all_in_one/super_tool"]


def test_trifecta_two_connected_tools() -> None:
    """Two connected tools that together cover all 3 caps → trifecta."""
    cfg = {
        "mcpServers": {
            "srv": {
                "tools": [
                    {
                        "name": "fetch_and_read_secret",
                        "description": (
                            "Browse webpage URL HTML and get private secret credentials."
                        ),
                    },
                    {
                        "name": "exfil_tool",
                        "description": "Send and transmit data via webhook.",
                    },
                ]
            }
        }
    }
    result = analyze_trifecta(parse_mcp_config(cfg))
    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert len(finding.path) >= 1


# ---------------------------------------------------------------------------
# analyze_trifecta — ambiguity rate
# ---------------------------------------------------------------------------


def test_ambiguity_rate_zero_when_all_definite() -> None:
    cfg = {
        "mcpServers": {
            "srv": {
                "tools": [
                    {"name": "write_data", "description": "Write some data."},
                ]
            }
        }
    }
    result = analyze_trifecta(parse_mcp_config(cfg))
    # "write_data" has write cap only → all caps False → not ambiguous
    assert result.ambiguity_rate == 0.0


def test_ambiguity_rate_one_when_all_unknown() -> None:
    cfg = {
        "mcpServers": {
            "srv": {
                "tools": [
                    # "exec" cap → can_exfiltrate=unknown; "read" cap → rpd=unknown, suc=unknown
                    {"name": "run_exec", "description": "Execute and run a command."},
                ]
            }
        }
    }
    result = analyze_trifecta(parse_mcp_config(cfg))
    assert result.ambiguity_rate == 1.0


# ---------------------------------------------------------------------------
# Existing fixtures — no regressions
# ---------------------------------------------------------------------------


def test_claude_desktop_profiles_produced() -> None:
    mcp = parse_mcp_file(FIXTURES / "claude_desktop.json")
    result = analyze_trifecta(mcp)
    assert len(result.profiles) == len(mcp.nodes)


def test_github_brave_profiles_produced() -> None:
    mcp = parse_mcp_file(FIXTURES / "github_brave.json")
    result = analyze_trifecta(mcp)
    assert len(result.profiles) == len(mcp.nodes)


def test_nonstandard_profiles_produced() -> None:
    mcp = parse_mcp_file(FIXTURES / "nonstandard.json")
    result = analyze_trifecta(mcp)
    assert len(result.profiles) == len(mcp.nodes)


def test_claude_desktop_read_file_rpd_profile() -> None:
    """read_file on filesystem server: has fs+read caps → rpd=unknown (fail-safe)."""
    mcp = parse_mcp_file(FIXTURES / "claude_desktop.json")
    result = analyze_trifecta(mcp)
    key = "filesystem/read_file"
    assert key in result.profiles
    profile = result.profiles[key]
    # read + fs caps without private keywords → unknown
    assert profile.reads_private_data.is_risk_present() is True


def test_claude_desktop_fetch_suc_profile() -> None:
    """fetch tool: url keyword → sees_untrusted_content=True."""
    mcp = parse_mcp_file(FIXTURES / "claude_desktop.json")
    result = analyze_trifecta(mcp)
    key = "fetch/fetch"
    assert key in result.profiles
    profile = result.profiles[key]
    assert profile.sees_untrusted_content.value is True


# ---------------------------------------------------------------------------
# Migration V3 files
# ---------------------------------------------------------------------------


def test_v3_up_migration_exists() -> None:
    assert (MIGRATIONS_DIR / "V3__add_security_caps.up.sql").exists()


def test_v3_down_migration_exists() -> None:
    assert (MIGRATIONS_DIR / "V3__add_security_caps.down.sql").exists()


def test_v3_up_adds_security_caps_column() -> None:
    sql = (MIGRATIONS_DIR / "V3__add_security_caps.up.sql").read_text()
    assert "security_caps" in sql.lower()
    assert "alter table" in sql.lower()


def test_v3_up_has_partial_index() -> None:
    sql = (MIGRATIONS_DIR / "V3__add_security_caps.up.sql").read_text()
    assert "create index" in sql.lower()
    assert "trifecta" in sql.lower()
    # Partial index must reference all three cap paths
    assert "reads_private_data" in sql
    assert "sees_untrusted_content" in sql
    assert "can_exfiltrate" in sql


def test_v3_down_drops_security_caps_column() -> None:
    sql = (MIGRATIONS_DIR / "V3__add_security_caps.down.sql").read_text()
    assert "security_caps" in sql.lower()
    assert "drop column" in sql.lower()


# ---------------------------------------------------------------------------
# analyzer module is importable
# ---------------------------------------------------------------------------


def test_analyzer_module_importable() -> None:
    import importlib

    mod = importlib.import_module("analyzer.trifecta")
    assert hasattr(mod, "analyze_trifecta")
    assert hasattr(mod, "tag_tool")
    assert hasattr(mod, "TrifectaResult")
    assert hasattr(mod, "TrifectaFinding")
    assert hasattr(mod, "SecurityProfile")
    assert hasattr(mod, "CapTag")
