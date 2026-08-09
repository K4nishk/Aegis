"""
db/migrate.py — Minimal migration runner for Aegis DDL.

Usage:
    python db/migrate.py up   [--dsn DSN]
    python db/migrate.py down [--dsn DSN]

DSN defaults to the DATABASE_URL environment variable.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
UP_SQL = MIGRATIONS_DIR / "V1__initial_schema.up.sql"
DOWN_SQL = MIGRATIONS_DIR / "V1__initial_schema.down.sql"


def _run_sql(dsn: str, sql_path: Path) -> None:
    try:
        import psycopg2  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        print(
            "psycopg2 not installed — install with: pip install psycopg2-binary",
            file=sys.stderr,
        )
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
        print(
            "No DSN provided. Set DATABASE_URL or pass --dsn.",
            file=sys.stderr,
        )
        return 1

    sql_path = UP_SQL if args.direction == "up" else DOWN_SQL
    if not sql_path.exists():
        print(f"Migration file not found: {sql_path}", file=sys.stderr)
        return 1

    _run_sql(args.dsn, sql_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
