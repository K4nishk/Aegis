"""db/migrate.py — Idempotent migration runner for Aegis DDL (KCH-33).

Discovers all V*__*.up.sql files, tracks applied versions in a
schema_migrations table, and applies only what is pending.  Safe to run
on every container start — re-running changes nothing.

Usage:
    python db/migrate.py up   [--dsn DSN]
    python db/migrate.py down [--dsn DSN]

DSN defaults to the DATABASE_URL environment variable.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

# Backward-compat aliases checked by tests/db/test_migrations.py
UP_SQL = MIGRATIONS_DIR / "V1__initial_schema.up.sql"
DOWN_SQL = MIGRATIONS_DIR / "V1__initial_schema.down.sql"

_VERSION_RE = re.compile(r"^V(\d+)__.*\.up\.sql$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover_up_migrations() -> list[tuple[int, Path]]:
    """Return [(version, path), ...] sorted by version number."""
    results: list[tuple[int, Path]] = []
    for path in MIGRATIONS_DIR.glob("*.up.sql"):
        m = _VERSION_RE.match(path.name)
        if m:
            results.append((int(m.group(1)), path))
    return sorted(results, key=lambda x: x[0])


def run_all_up(dsn: str) -> int:
    """Apply all pending up-migrations idempotently. Returns 0 on success."""
    try:
        import psycopg2  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        print("psycopg2 not installed — pip install psycopg2-binary", file=sys.stderr)
        raise SystemExit(1) from exc

    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    try:
        # Create tracking table (idempotent)
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version    INTEGER     PRIMARY KEY,
                    filename   TEXT        NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        conn.commit()

        # Determine which versions are already applied
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migrations ORDER BY version")
            applied: set[int] = {row[0] for row in cur.fetchall()}

        for version, path in _discover_up_migrations():
            if version in applied:
                print(f"Skip (already applied): {path.name}")
                continue
            sql = path.read_text(encoding="utf-8")
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    cur.execute(
                        "INSERT INTO schema_migrations (version, filename) VALUES (%s, %s)",
                        (version, path.name),
                    )
                conn.commit()
                print(f"Applied: {path.name}")
            except Exception:
                conn.rollback()
                raise

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return 0


def _run_sql(dsn: str, sql_path: Path) -> None:
    """Execute a single SQL file in one transaction."""
    try:
        import psycopg2  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        print("psycopg2 not installed — pip install psycopg2-binary", file=sys.stderr)
        raise SystemExit(1) from exc

    sql = sql_path.read_text(encoding="utf-8")
    conn = psycopg2.connect(dsn)
    try:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        print(f"Applied: {sql_path.name}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aegis migration runner")
    parser.add_argument("direction", choices=["up", "down"])
    parser.add_argument("--dsn", default=os.environ.get("DATABASE_URL", ""))
    args = parser.parse_args(argv)

    if not args.dsn:
        print("No DSN provided. Set DATABASE_URL or pass --dsn.", file=sys.stderr)
        return 1

    if args.direction == "up":
        return run_all_up(args.dsn)

    # down: apply V1 down SQL (drops all tables)
    if not DOWN_SQL.exists():
        print(f"Migration file not found: {DOWN_SQL}", file=sys.stderr)
        return 1
    _run_sql(args.dsn, DOWN_SQL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
