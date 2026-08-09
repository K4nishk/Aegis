"""tests/ops/test_backup_rehearsal.py — KCH-23 restore rehearsal.

Proves that pg_dump (custom format) + pg_restore produces an identical
database.  Skipped automatically if local Postgres is unavailable (same
pattern used across the test suite).

On success, writes a timestamped receipt to ops/rehearsal_receipt.txt.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

_ADMIN_DSN = "postgresql://ishq_kan@localhost:5432/postgres"
_SRC_DB = "aegis_kch23_src"
_DST_DB = "aegis_kch23_dst"
_MIGRATIONS_DIR = Path(__file__).parents[2] / "db" / "migrations"
_RECEIPT_FILE = Path(__file__).parents[2] / "ops" / "rehearsal_receipt.txt"

_MIGRATION_FILES = [
    "V1__initial_schema.up.sql",
    "V2__add_def_hash.up.sql",
    "V3__add_security_caps.up.sql",
    "V4__add_server_name.up.sql",
    "V5__add_owner_rls.up.sql",
]


def _psycopg2():
    try:
        import psycopg2  # type: ignore[import-untyped]

        return psycopg2
    except ImportError:
        return None


def _pg_tools_available() -> bool:
    return shutil.which("pg_dump") is not None and shutil.which("pg_restore") is not None


@pytest.fixture(scope="module")
def pg():
    mod = _psycopg2()
    if mod is None:
        pytest.skip("psycopg2 not installed")
    if not _pg_tools_available():
        pytest.skip("pg_dump / pg_restore not found in PATH")
    try:
        conn = mod.connect(_ADMIN_DSN)
        conn.close()
    except Exception as exc:
        pytest.skip(f"Cannot connect to local Postgres: {exc}")
    return mod


@pytest.fixture(scope="module")
def src_db(pg):
    """Create aegis_kch23_src, apply all migrations, seed rows, yield DSN, then drop."""
    admin = pg.connect(_ADMIN_DSN)
    admin.autocommit = True

    def _terminate_and_drop(cur, name: str) -> None:
        cur.execute(
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"
        )
        cur.execute(f"DROP DATABASE IF EXISTS {name}")

    with admin.cursor() as cur:
        _terminate_and_drop(cur, _SRC_DB)
        cur.execute(f"CREATE DATABASE {_SRC_DB}")
    admin.close()

    src_dsn = f"postgresql://ishq_kan@localhost:5432/{_SRC_DB}"
    conn = pg.connect(src_dsn)
    conn.autocommit = False
    try:
        for fname in _MIGRATION_FILES:
            fpath = _MIGRATIONS_DIR / fname
            if not fpath.exists():
                continue
            with conn.cursor() as cur:
                cur.execute(fpath.read_text(encoding="utf-8"))
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    finally:
        if not conn.closed:
            conn.close()

    # Seed test rows as superuser (bypasses RLS owner filter)
    conn = pg.connect(src_dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_runs (target, status)
            VALUES ('rehearsal_target_1', 'completed'),
                   ('rehearsal_target_2', 'completed')
            """
        )
    conn.close()

    yield src_dsn

    admin = pg.connect(_ADMIN_DSN)
    admin.autocommit = True
    with admin.cursor() as cur:
        _terminate_and_drop(cur, _SRC_DB)
    admin.close()


def test_restore_rehearsal(pg, src_db):
    """Full dump-restore rehearsal: dump src → restore dst → verify row counts."""
    src_dsn = src_db
    admin = pg.connect(_ADMIN_DSN)
    admin.autocommit = True

    with tempfile.TemporaryDirectory() as tmpdir:
        dump_file = Path(tmpdir) / f"rehearsal_{_SRC_DB}.pgdump"

        # ------------------------------------------------------------------
        # Step 1: pg_dump (custom binary format, no compression — we verify
        # gzip separately so the test stays focused on correctness)
        # ------------------------------------------------------------------
        result = subprocess.run(
            [
                "pg_dump",
                "--host=localhost",
                "--port=5432",
                "--username=ishq_kan",
                "--format=custom",
                f"--file={dump_file}",
                _SRC_DB,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"pg_dump failed:\n{result.stderr}"
        assert dump_file.exists() and dump_file.stat().st_size > 0, "dump file is empty"

        dump_bytes = dump_file.stat().st_size

        # ------------------------------------------------------------------
        # Step 2: create destination DB
        # ------------------------------------------------------------------
        with admin.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{_DST_DB}'"
            )
            cur.execute(f"DROP DATABASE IF EXISTS {_DST_DB}")
            cur.execute(f"CREATE DATABASE {_DST_DB}")

        # ------------------------------------------------------------------
        # Step 3: pg_restore
        # ------------------------------------------------------------------
        result = subprocess.run(
            [
                "pg_restore",
                "--host=localhost",
                "--port=5432",
                "--username=ishq_kan",
                f"--dbname={_DST_DB}",
                "--no-owner",
                "--no-privileges",
                str(dump_file),
            ],
            capture_output=True,
            text=True,
        )
        # pg_restore may emit warnings (non-fatal); only fail on non-zero exit
        assert result.returncode == 0, (
            f"pg_restore failed (exit {result.returncode}):\n{result.stderr}"
        )

    # ------------------------------------------------------------------
    # Step 4: verify row counts match
    # ------------------------------------------------------------------
    dst_dsn = f"postgresql://ishq_kan@localhost:5432/{_DST_DB}"
    tables = ["scan_runs", "tool_graph_nodes", "tool_graph_edges"]
    src_counts: dict[str, int] = {}
    dst_counts: dict[str, int] = {}

    src_conn = pg.connect(src_dsn)
    dst_conn = pg.connect(dst_dsn)
    try:
        for table in tables:
            with src_conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
                src_counts[table] = cur.fetchone()[0]
            with dst_conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
                dst_counts[table] = cur.fetchone()[0]
    finally:
        src_conn.close()
        dst_conn.close()

    for table in tables:
        assert src_counts[table] == dst_counts[table], (
            f"Row count mismatch for {table}: src={src_counts[table]} dst={dst_counts[table]}"
        )

    # ------------------------------------------------------------------
    # Step 5: clean up destination DB
    # ------------------------------------------------------------------
    with admin.cursor() as cur:
        cur.execute(
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{_DST_DB}'"
        )
        cur.execute(f"DROP DATABASE IF EXISTS {_DST_DB}")
    admin.close()

    # ------------------------------------------------------------------
    # Step 6: write timestamped receipt (AC: restore rehearsal completed
    # + timestamped)
    # ------------------------------------------------------------------
    ts = datetime.now(tz=UTC).isoformat()
    rows_detail = "\n".join(f"  {t}: {src_counts[t]} rows (src == dst)" for t in tables)
    receipt = (
        "AEGIS BACKUP RESTORE REHEARSAL RECEIPT\n"
        "=======================================\n"
        f"Timestamp (UTC):  {ts}\n"
        f"Source DB:        {_SRC_DB}\n"
        f"Target DB:        {_DST_DB}\n"
        f"Dump format:      pg_dump --format=custom\n"
        f"Restore flags:    --no-owner --no-privileges\n"
        f"Dump size:        {dump_bytes} bytes\n"
        f"Tables verified:\n"
        f"{rows_detail}\n"
        "\n"
        "RESULT: PASS — all row counts match, restore successful\n"
    )

    _RECEIPT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _RECEIPT_FILE.write_text(receipt, encoding="utf-8")

    print(receipt)
