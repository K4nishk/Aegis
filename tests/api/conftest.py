"""tests/api/conftest.py — Test DB fixture for KCH-11 integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

_MIGRATIONS_DIR = Path(__file__).parents[2] / "db" / "migrations"
_MIGRATION_FILES = [
    "V1__initial_schema.up.sql",
    "V2__add_def_hash.up.sql",
    "V3__add_security_caps.up.sql",
    "V4__add_server_name.up.sql",
    "V5__add_owner_rls.up.sql",
]

_TEST_DB = "aegis_kch17_test"
_ADMIN_DSN = "postgresql://ishq_kan@localhost:5432/postgres"
_TEST_DSN = f"postgresql://ishq_kan@localhost:5432/{_TEST_DB}"


def _psycopg2():
    try:
        import psycopg2  # type: ignore[import-untyped]

        return psycopg2
    except ImportError:
        return None


@pytest.fixture(scope="session")
def test_db_dsn():
    """Create a scratch DB, run all migrations, yield DSN, then drop."""
    pg = _psycopg2()
    if pg is None:
        pytest.skip("psycopg2 not installed")

    try:
        admin = pg.connect(_ADMIN_DSN)
    except Exception as exc:
        pytest.skip(f"Cannot connect to local Postgres: {exc}")

    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS {_TEST_DB}")
        cur.execute(f"CREATE DATABASE {_TEST_DB}")
    admin.close()

    # Run all migrations in order
    test_conn = pg.connect(_TEST_DSN)
    test_conn.autocommit = False
    try:
        for fname in _MIGRATION_FILES:
            fpath = _MIGRATIONS_DIR / fname
            if not fpath.exists():
                continue
            sql = fpath.read_text(encoding="utf-8")
            with test_conn.cursor() as cur:
                cur.execute(sql)
        test_conn.commit()
    except Exception:
        test_conn.rollback()
        test_conn.close()
        raise
    finally:
        if not test_conn.closed:
            test_conn.close()

    yield _TEST_DSN

    # Teardown
    admin = pg.connect(_ADMIN_DSN)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{_TEST_DB}'"
        )
        cur.execute(f"DROP DATABASE IF EXISTS {_TEST_DB}")
    admin.close()
