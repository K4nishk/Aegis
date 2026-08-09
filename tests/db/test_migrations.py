"""
tests/db/test_migrations.py

Structural tests for Aegis DDL migrations (V1).
These tests parse the SQL text directly — no live database required.

Integration tests (require DATABASE_URL) are skipped automatically when
the env var is absent.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

MIGRATIONS_DIR = Path(__file__).parent.parent.parent / "db" / "migrations"
UP_SQL_PATH = MIGRATIONS_DIR / "V1__initial_schema.up.sql"
DOWN_SQL_PATH = MIGRATIONS_DIR / "V1__initial_schema.down.sql"


@pytest.fixture(scope="module")
def up_sql() -> str:
    return UP_SQL_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def down_sql() -> str:
    return DOWN_SQL_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------


def test_up_migration_file_exists() -> None:
    assert UP_SQL_PATH.exists(), f"Missing: {UP_SQL_PATH}"


def test_down_migration_file_exists() -> None:
    assert DOWN_SQL_PATH.exists(), f"Missing: {DOWN_SQL_PATH}"


# ---------------------------------------------------------------------------
# Required tables present in up migration
# ---------------------------------------------------------------------------

REQUIRED_TABLES = [
    "scan_runs",
    "tool_graph_nodes",
    "tool_graph_edges",
    "findings",
    "ai_bom",
    "audit_log",
]


@pytest.mark.parametrize("table", REQUIRED_TABLES)
def test_up_creates_table(up_sql: str, table: str) -> None:
    pattern = rf"CREATE TABLE\s+{re.escape(table)}\s*[\(\n]"
    assert re.search(pattern, up_sql, re.IGNORECASE), (
        f"CREATE TABLE {table} not found in up migration"
    )


# ---------------------------------------------------------------------------
# Trifecta boolean columns in tool_graph_nodes
# ---------------------------------------------------------------------------

TRIFECTA_COLS = ["is_sandboxed", "is_auditable", "is_pinned"]


@pytest.mark.parametrize("col", TRIFECTA_COLS)
def test_trifecta_columns_present(up_sql: str, col: str) -> None:
    assert col in up_sql, f"Trifecta column '{col}' not found in up migration"


def test_trifecta_columns_are_boolean(up_sql: str) -> None:
    for col in TRIFECTA_COLS:
        pattern = rf"{re.escape(col)}\s+BOOLEAN"
        assert re.search(pattern, up_sql, re.IGNORECASE), f"Column {col} is not declared as BOOLEAN"


# ---------------------------------------------------------------------------
# JSONB caps column
# ---------------------------------------------------------------------------


def test_caps_jsonb_column(up_sql: str) -> None:
    assert re.search(r"caps\s+JSONB", up_sql, re.IGNORECASE), (
        "caps JSONB column not found in up migration"
    )


# ---------------------------------------------------------------------------
# Partial index on all-trifecta-true
# ---------------------------------------------------------------------------


def test_partial_index_on_trifecta(up_sql: str) -> None:
    # Must contain a WHERE clause with all three trifecta columns
    where_blocks = re.findall(r"WHERE\s+(.+?)(?:;|\n\n)", up_sql, re.IGNORECASE | re.DOTALL)
    trifecta_where = [b for b in where_blocks if all(col in b for col in TRIFECTA_COLS)]
    assert trifecta_where, (
        "No partial index WHERE clause referencing all three trifecta columns found"
    )


# ---------------------------------------------------------------------------
# GIN index on caps
# ---------------------------------------------------------------------------


def test_gin_index_on_caps(up_sql: str) -> None:
    assert re.search(r"USING\s+GIN\s*\(\s*caps\s*\)", up_sql, re.IGNORECASE), (
        "GIN index on caps not found in up migration"
    )


# ---------------------------------------------------------------------------
# audit_log: RANGE partitioning
# ---------------------------------------------------------------------------


def test_audit_log_range_partition(up_sql: str) -> None:
    assert re.search(
        r"audit_log\b.+?PARTITION\s+BY\s+RANGE",
        up_sql,
        re.IGNORECASE | re.DOTALL,
    ), "audit_log PARTITION BY RANGE not found"


def test_audit_log_monthly_partitions_present(up_sql: str) -> None:
    # Should have at least 12 monthly partitions
    partitions = re.findall(r"audit_log_\d{4}_\d{2}", up_sql)
    assert len(partitions) >= 12, f"Expected >=12 monthly partitions, found {len(partitions)}"


def test_audit_log_partition_covers_current_month(up_sql: str) -> None:
    # 2026-08 (today per system) must have a partition
    assert "audit_log_2026_08" in up_sql, "Partition for 2026-08 (current month) not found"


# ---------------------------------------------------------------------------
# audit_log: BRIN index
# ---------------------------------------------------------------------------


def test_audit_log_brin_index(up_sql: str) -> None:
    assert re.search(r"USING\s+BRIN\s*\(\s*ts\s*\)", up_sql, re.IGNORECASE), (
        "BRIN index on ts not found for audit_log"
    )


# ---------------------------------------------------------------------------
# audit_log: append-only via REVOKE
# ---------------------------------------------------------------------------


def test_audit_log_revoke_update_delete(up_sql: str) -> None:
    assert re.search(
        r"REVOKE\s+UPDATE\s*,\s*DELETE\s+ON\s+audit_log\s+FROM\s+aegis_app",
        up_sql,
        re.IGNORECASE,
    ), "REVOKE UPDATE, DELETE ON audit_log FROM aegis_app not found"


# ---------------------------------------------------------------------------
# Down migration drops all required tables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "table",
    ["audit_log", "findings", "ai_bom", "tool_graph_edges", "tool_graph_nodes", "scan_runs"],
)
def test_down_drops_table(down_sql: str, table: str) -> None:
    assert re.search(
        rf"DROP TABLE\s+IF EXISTS\s+{re.escape(table)}\b",
        down_sql,
        re.IGNORECASE,
    ), f"DROP TABLE IF EXISTS {table} not found in down migration"


# ---------------------------------------------------------------------------
# Migration runner module is importable
# ---------------------------------------------------------------------------


def test_migrate_module_importable() -> None:
    import importlib

    mod = importlib.import_module("db.migrate")
    assert hasattr(mod, "main")
    assert hasattr(mod, "UP_SQL")
    assert hasattr(mod, "DOWN_SQL")


# ---------------------------------------------------------------------------
# Integration tests (skipped when DATABASE_URL is absent)
# ---------------------------------------------------------------------------

requires_db = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set — skipping live DB tests",
)


@requires_db
def test_integration_up_applies_clean() -> None:
    """Apply up migration and verify tables exist."""
    import psycopg2  # type: ignore[import-untyped]

    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(UP_SQL_PATH.read_text(encoding="utf-8"))
            for table in REQUIRED_TABLES:
                cur.execute(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_name = %s AND table_schema = 'public'",
                    (table,),
                )
                assert cur.fetchone() is not None, f"Table {table} missing after up"
    finally:
        conn.close()


@requires_db
def test_integration_down_cleans_up() -> None:
    """Apply down migration and verify tables are gone."""
    import psycopg2  # type: ignore[import-untyped]

    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(DOWN_SQL_PATH.read_text(encoding="utf-8"))
            for table in REQUIRED_TABLES:
                cur.execute(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_name = %s AND table_schema = 'public'",
                    (table,),
                )
                assert cur.fetchone() is None, f"Table {table} still present after down"
    finally:
        conn.close()
