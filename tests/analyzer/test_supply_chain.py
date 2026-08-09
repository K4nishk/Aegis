"""
tests/analyzer/test_supply_chain.py — Unit tests for supply-chain risk scanner (KCH-20).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.supply_chain import (
    SupplyChainFinding,
    SupplyChainResult,
    scan_mcp_config,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _highs(result: SupplyChainResult) -> list[SupplyChainFinding]:
    return [f for f in result.findings if f.severity == "HIGH"]


def _mediums(result: SupplyChainResult) -> list[SupplyChainFinding]:
    return [f for f in result.findings if f.severity == "MEDIUM"]


def _risks(result: SupplyChainResult) -> set[str]:
    return {f.risk for f in result.findings}


# ---------------------------------------------------------------------------
# npx — unpinned (no @version) → HIGH
# ---------------------------------------------------------------------------


class TestNpxUnpinned:
    def test_npx_no_version_is_high(self):
        cfg = {"mcpServers": {"s": {"command": "npx", "args": ["@mcp/server-foo"]}}}
        result = scan_mcp_config(cfg)
        assert result.high_count >= 1
        assert "unpinned_version" in _risks(result)
        assert not result.clean

    def test_npx_dash_y_flag_is_high_auto_install(self):
        cfg = {"mcpServers": {"s": {"command": "npx", "args": ["-y", "@mcp/server-foo"]}}}
        result = scan_mcp_config(cfg)
        risks = _risks(result)
        assert result.high_count >= 2  # auto_install + unpinned_version
        assert "auto_install" in risks
        assert "unpinned_version" in risks

    def test_npx_dash_yes_long_flag(self):
        cfg = {"mcpServers": {"s": {"command": "npx", "args": ["--yes", "@mcp/server-foo"]}}}
        result = scan_mcp_config(cfg)
        assert "auto_install" in _risks(result)

    def test_npx_with_semver_is_clean(self):
        cfg = {"mcpServers": {"s": {"command": "npx", "args": ["@mcp/server-foo@1.2.3"]}}}
        result = scan_mcp_config(cfg)
        # No unpinned_version finding; auto_install not present either
        assert "unpinned_version" not in _risks(result)
        assert "auto_install" not in _risks(result)

    def test_npx_with_semver_major_only(self):
        """Single-component version is semver-like — treat as pinned."""
        cfg = {"mcpServers": {"s": {"command": "npx", "args": ["some-pkg@3"]}}}
        result = scan_mcp_config(cfg)
        assert "unpinned_version" not in _risks(result)

    def test_npx_tag_version_is_medium(self):
        cfg = {"mcpServers": {"s": {"command": "npx", "args": ["@mcp/foo@latest"]}}}
        result = scan_mcp_config(cfg)
        assert "tag_not_semver" in _risks(result)
        assert result.high_count == 0  # no auto_install, no unpinned

    def test_npx_beta_tag_is_medium(self):
        cfg = {"mcpServers": {"s": {"command": "npx", "args": ["pkg@beta"]}}}
        result = scan_mcp_config(cfg)
        assert "tag_not_semver" in _risks(result)


# ---------------------------------------------------------------------------
# uvx — unpinned (no ==version) → HIGH
# ---------------------------------------------------------------------------


class TestUvxUnpinned:
    def test_uvx_no_pin_is_high(self):
        cfg = {"mcpServers": {"s": {"command": "uvx", "args": ["mcp-server-fetch"]}}}
        result = scan_mcp_config(cfg)
        assert result.high_count >= 1
        assert "unpinned_version" in _risks(result)

    def test_uvx_exact_pin_is_clean(self):
        cfg = {"mcpServers": {"s": {"command": "uvx", "args": ["mcp-server-fetch==0.6.1"]}}}
        result = scan_mcp_config(cfg)
        assert "unpinned_version" not in _risks(result)
        assert result.clean

    def test_uvx_range_constraint_is_medium(self):
        cfg = {"mcpServers": {"s": {"command": "uvx", "args": ["mcp-server-fetch>=0.6"]}}}
        result = scan_mcp_config(cfg)
        assert "tag_not_semver" in _risks(result)
        assert result.high_count == 0


# ---------------------------------------------------------------------------
# Clean configs
# ---------------------------------------------------------------------------


class TestCleanConfigs:
    def test_empty_config_is_clean(self):
        result = scan_mcp_config({})
        assert result.clean
        assert result.findings == []

    def test_non_npx_command_ignored(self):
        cfg = {"mcpServers": {"s": {"command": "python", "args": ["-m", "server"]}}}
        result = scan_mcp_config(cfg)
        assert result.clean

    def test_servers_key_alias(self):
        cfg = {"servers": {"s": {"command": "npx", "args": ["@pkg/name@1.0.0"]}}}
        result = scan_mcp_config(cfg)
        assert result.clean

    def test_single_server_shorthand_npx_clean(self):
        cfg = {"command": "npx", "args": ["my-tool@2.0.1"]}
        result = scan_mcp_config(cfg)
        assert result.clean

    def test_single_server_shorthand_npx_unpinned(self):
        cfg = {"command": "npx", "args": ["my-tool"]}
        result = scan_mcp_config(cfg)
        assert not result.clean


# ---------------------------------------------------------------------------
# Fixture files — known_bad uses npx -y without version pin (HIGH expected)
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_known_bad_fixture_has_supply_chain_highs(self):
        """known_bad.json uses 'npx -y @example/mcp-evil' — should flag HIGH."""
        path = FIXTURES / "known_bad.json"
        if not path.exists():
            pytest.skip("known_bad fixture not found")
        cfg = json.loads(path.read_text())
        result = scan_mcp_config(cfg)
        assert result.high_count >= 1

    def test_github_brave_fixture_has_supply_chain_highs(self):
        """github_brave.json uses 'npx -y' without version pins."""
        path = FIXTURES / "github_brave.json"
        if not path.exists():
            pytest.skip("github_brave fixture not found")
        cfg = json.loads(path.read_text())
        result = scan_mcp_config(cfg)
        assert result.high_count >= 1

    def test_claude_desktop_fixture_scanned(self):
        """claude_desktop.json uses uvx mcp-server-fetch (unpinned)."""
        path = FIXTURES / "claude_desktop.json"
        if not path.exists():
            pytest.skip("claude_desktop fixture not found")
        cfg = json.loads(path.read_text())
        result = scan_mcp_config(cfg)
        # At least the uvx call without == is flagged
        assert result.high_count >= 1


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


class TestResultDataclass:
    def test_high_count_property(self):
        result = SupplyChainResult()
        result.findings = [
            SupplyChainFinding("s", "npx", [], "unpinned_version", "HIGH", "d"),
            SupplyChainFinding("s", "npx", [], "auto_install", "HIGH", "d"),
            SupplyChainFinding("s", "npx", [], "tag_not_semver", "MEDIUM", "d"),
        ]
        assert result.high_count == 2
        assert result.medium_count == 1

    def test_servers_scanned_count(self):
        cfg = {
            "mcpServers": {
                "a": {"command": "npx", "args": ["pkg@1.0.0"]},
                "b": {"command": "uvx", "args": ["tool==0.1.0"]},
            }
        }
        result = scan_mcp_config(cfg)
        assert result.servers_scanned == 2
