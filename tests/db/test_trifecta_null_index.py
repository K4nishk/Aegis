"""
tests/db/test_trifecta_null_index.py

Integration tests for KCH-25: NULL fail-safe fix in the trifecta partial index.

Requires a local Postgres instance (superuser 'ishq_kan' on localhost:5432).
Skipped automatically when Postgres is unavailable.

The V7 migration drops and recreates idx_tool_graph_nodes_trifecta_risk with
COALESCE so that a missing JSON key maps to 'unknown' (risk-present) instead
of NULL (silently excluded).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

_MIGRATIONS_DIR = Path(__file__).parents[2] / "db" / "migrations"
_MIGRATION_FILES = [
    "V1__initial_schema.up.sql",
    "V2__add_def_hash.up.sql",
    "V3__add_security_caps.up.sql",
    "V4__add_server_name.up.sql",
    "V5__add_owner_rls.up.sql",
    "V6__dynamic_probe_results.up.sql",
    "V7__fix_trifecta_null_index.up.sql",
]

_TEST_DB = "aegis_kch25_test"
_ADMIN_DSN = "postgresql://ishq_kan@localhost:5432/postgres"
_TEST_DSN = f"postgresql://ishq_kan@localhost:5432/{_TEST_DB}"

# sentinel owner UUID — V5 default for anonymous/dev mode
_OWNER_ID = "00000000-0000-0000-0000-000000000001"


def _psycopg2():
    try:
        import psycopg2  # type: ignore[import-untyped]

        return psycopg2
    except ImportError:
        return None


@pytest.fixture(scope="module")
def db_conn():
    """Scratch DB with all migrations applied; yields a psycopg2 connection."""
    pg = _psycopg2()
    if pg is None:
        pytest.skip("psycopg2 not installed")

    try:
        admin = pg.connect(_ADMIN_DSN)
    except Exception as exc:
        pytest.skip(f"Cannot connect to local Postgres: {exc}")

    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{_TEST_DB}'"
        )
        cur.execute(f"DROP DATABASE IF EXISTS {_TEST_DB}")
        cur.execute(f"CREATE DATABASE {_TEST_DB}")
    admin.close()

    conn = pg.connect(_TEST_DSN)
    conn.autocommit = False
    try:
        for fname in _MIGRATION_FILES:
            fpath = _MIGRATIONS_DIR / fname
            if not fpath.exists():
                pytest.skip(f"Migration file missing: {fname}")
            sql = fpath.read_text(encoding="utf-8")
            with conn.cursor() as cur:
                cur.execute(sql)
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise

    # Set app.user_id at session level so RLS policies pass for the owner sentinel.
    with conn.cursor() as cur:
        cur.execute(f"SET app.user_id = '{_OWNER_ID}'")
    conn.commit()

    yield conn

    conn.close()

    # Teardown: drop scratch DB
    try:
        admin = pg.connect(_ADMIN_DSN)
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute(
                f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{_TEST_DB}'"
            )
            cur.execute(f"DROP DATABASE IF EXISTS {_TEST_DB}")
        admin.close()
    except Exception:
        pass  # best-effort teardown


def _insert_scan_run(cur) -> str:
    """Insert a minimal scan_run row and return its UUID string."""
    scan_id = str(uuid.uuid4())
    cur.execute(
        """
        INSERT INTO scan_runs (id, owner_id, status, target)
        VALUES (%s, %s::uuid, 'completed', 'test.json')
        """,
        (scan_id, _OWNER_ID),
    )
    return scan_id


def _insert_node(cur, scan_id: str, node_key: str, security_caps: dict | None) -> str:
    """Insert a tool_graph_nodes row and return its UUID."""
    node_id = str(uuid.uuid4())
    caps_json = json.dumps(security_caps) if security_caps is not None else None
    cur.execute(
        """
        INSERT INTO tool_graph_nodes
            (id, scan_run_id, node_key, tool_name, server_name,
             caps, def_hash, security_caps)
        VALUES
            (%s, %s::uuid, %s, %s, %s,
             %s::jsonb, %s, %s::jsonb)
        """,
        (
            node_id,
            scan_id,
            node_key,
            node_key,
            "test_server",
            json.dumps([]),
            "deadbeef",
            caps_json,
        ),
    )
    return node_id


def _trifecta_node_ids(cur, scan_id: str) -> set[str]:
    """Return node IDs selected by the trifecta partial-index predicate."""
    cur.execute(
        """
        SELECT id::text FROM tool_graph_nodes
        WHERE
            scan_run_id = %s::uuid
            AND security_caps IS NOT NULL
            AND COALESCE(security_caps #>> '{reads_private_data,value}',    'unknown') <> 'false'
            AND COALESCE(security_caps #>> '{sees_untrusted_content,value}', 'unknown') <> 'false'
            AND COALESCE(security_caps #>> '{can_exfiltrate,value}',         'unknown') <> 'false'
        """,
        (scan_id,),
    )
    return {row[0] for row in cur.fetchall()}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_node_with_all_three_caps_true_included(db_conn):
    """Baseline: all three caps present and true → node is included."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        caps = {
            "reads_private_data": {"value": "true", "confidence": "high"},
            "sees_untrusted_content": {"value": "true", "confidence": "high"},
            "can_exfiltrate": {"value": "true", "confidence": "high"},
        }
        node_id = _insert_node(cur, scan_id, "all_true", caps)
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id in found, "Node with all caps=true must be included"


def test_node_with_missing_cap_key_included(db_conn):
    """KCH-25 fix: a node missing one cap key must still be included (unknown = risk-present)."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        # can_exfiltrate key is entirely absent
        caps = {
            "reads_private_data": {"value": "true", "confidence": "high"},
            "sees_untrusted_content": {"value": "true", "confidence": "high"},
            # can_exfiltrate missing
        }
        node_id = _insert_node(cur, scan_id, "missing_exfil_key", caps)
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id in found, (
            "Node with a missing cap key must be included (NULL → unknown → risk-present)"
        )


def test_node_with_missing_all_cap_keys_included(db_conn):
    """A node with security_caps={} (all three keys absent) is still included."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        node_id = _insert_node(cur, scan_id, "empty_caps", {})
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id in found, (
            "Node with security_caps={} must be included (all keys missing → all unknown)"
        )


def test_node_with_explicit_false_reads_excluded(db_conn):
    """A node with reads_private_data=false must be excluded."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        caps = {
            "reads_private_data": {"value": "false", "confidence": "high"},
            "sees_untrusted_content": {"value": "true", "confidence": "high"},
            "can_exfiltrate": {"value": "true", "confidence": "high"},
        }
        node_id = _insert_node(cur, scan_id, "reads_false", caps)
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id not in found, (
            "Node with reads_private_data=false must be excluded from trifecta index"
        )


def test_node_with_explicit_false_suc_excluded(db_conn):
    """A node with sees_untrusted_content=false must be excluded."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        caps = {
            "reads_private_data": {"value": "true", "confidence": "high"},
            "sees_untrusted_content": {"value": "false", "confidence": "high"},
            "can_exfiltrate": {"value": "true", "confidence": "high"},
        }
        node_id = _insert_node(cur, scan_id, "suc_false", caps)
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id not in found, (
            "Node with sees_untrusted_content=false must be excluded from trifecta index"
        )


def test_node_with_explicit_false_exfil_excluded(db_conn):
    """A node with can_exfiltrate=false must be excluded."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        caps = {
            "reads_private_data": {"value": "true", "confidence": "high"},
            "sees_untrusted_content": {"value": "true", "confidence": "high"},
            "can_exfiltrate": {"value": "false", "confidence": "high"},
        }
        node_id = _insert_node(cur, scan_id, "exfil_false", caps)
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id not in found, (
            "Node with can_exfiltrate=false must be excluded from trifecta index"
        )


def test_node_with_unknown_string_cap_included(db_conn):
    """A node with explicit 'unknown' string value is included (risk-present)."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        caps = {
            "reads_private_data": {"value": "unknown", "confidence": "low"},
            "sees_untrusted_content": {"value": "true", "confidence": "high"},
            "can_exfiltrate": {"value": "true", "confidence": "high"},
        }
        node_id = _insert_node(cur, scan_id, "reads_unknown", caps)
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id in found, (
            "Node with reads_private_data=unknown must be included (risk-present)"
        )


def test_node_with_null_security_caps_excluded(db_conn):
    """A node where security_caps IS NULL is excluded (not yet tagged)."""
    with db_conn.cursor() as cur:
        scan_id = _insert_scan_run(cur)
        node_id = _insert_node(cur, scan_id, "null_security_caps", None)
        db_conn.commit()

        found = _trifecta_node_ids(cur, scan_id)
        assert node_id not in found, "Node with security_caps IS NULL must be excluded"


# ---------------------------------------------------------------------------
# Index existence test (SQL text level, no DB required)
# ---------------------------------------------------------------------------


def test_v7_up_migration_uses_coalesce():
    """V7 up migration SQL must use COALESCE for all three cap predicates."""
    sql = (_MIGRATIONS_DIR / "V7__fix_trifecta_null_index.up.sql").read_text()
    for cap in ("reads_private_data", "sees_untrusted_content", "can_exfiltrate"):
        assert f"COALESCE(security_caps #>> '{{{cap},value}}'" in sql, (
            f"COALESCE not found for {cap} in V7 up migration"
        )


def test_v7_down_migration_drops_and_recreates():
    """V7 down migration must DROP and recreate the index (restoring old definition)."""
    sql = (_MIGRATIONS_DIR / "V7__fix_trifecta_null_index.down.sql").read_text()
    assert "DROP INDEX IF EXISTS idx_tool_graph_nodes_trifecta_risk" in sql
    assert "CREATE INDEX" in sql
    # Down migration should NOT use COALESCE (it restores the old nullable definition)
    assert "COALESCE" not in sql, (
        "Down migration should restore the original index without COALESCE"
    )
