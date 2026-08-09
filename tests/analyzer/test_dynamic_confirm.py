"""tests/analyzer/test_dynamic_confirm.py — KCH-15 dynamic confirm probe tests.

Async tests run via asyncio.run() (no pytest-asyncio required).
DB integration tests are skipped when DATABASE_URL is not set.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from analyzer.dynamic_confirm import (
    CANNED_TRIFECTA_PROBE,
    DEFERRED_LABEL,
    ProbeResult,
    mock_target,
    persist_probe_result,
    run_probe_async,
    schedule_confirm,
)
from analyzer.trifecta import TrifectaFinding

# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

SAMPLE_FINDING = TrifectaFinding(
    path=[
        "known-bad::steal_credentials",
        "known-bad::inject_and_exfil",
        "known-bad::data_publisher",
    ],
    rpd_node="known-bad::steal_credentials",
    suc_node="known-bad::inject_and_exfil",
    exf_node="known-bad::data_publisher",
    confidence=0.9,
)


# ---------------------------------------------------------------------------
# ProbeSpec / constant tests
# ---------------------------------------------------------------------------


def test_deferred_label_value():
    assert DEFERRED_LABEL == "confirmatory, async, deferred"


def test_canned_probe_has_required_fields():
    spec = CANNED_TRIFECTA_PROBE
    assert spec.probe_id
    assert spec.scenario
    assert spec.prompt_template
    assert spec.confirm_keywords
    assert spec.label == DEFERRED_LABEL
    assert "{path}" in spec.prompt_template


def test_canned_probe_label_is_deferred():
    assert CANNED_TRIFECTA_PROBE.label == DEFERRED_LABEL


# ---------------------------------------------------------------------------
# run_probe_async — confirmed path
# ---------------------------------------------------------------------------


def test_run_probe_confirmed_with_mock_target():
    result = asyncio.run(run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, mock_target))
    assert result.outcome == "confirmed"
    assert result.label == DEFERRED_LABEL
    assert result.deferred is True
    assert result.probe_id == CANNED_TRIFECTA_PROBE.probe_id
    assert result.trifecta_path == SAMPLE_FINDING.path
    assert len(result.evidence["keywords_matched"]) > 0


# ---------------------------------------------------------------------------
# run_probe_async — denied path
# ---------------------------------------------------------------------------


def test_run_probe_denied_when_safe_target():
    async def safe_target(prompt: str) -> str:  # noqa: ARG001
        return "I cannot assist with that request."

    result = asyncio.run(run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, safe_target))
    assert result.outcome == "denied"
    assert result.label == DEFERRED_LABEL
    assert result.evidence["keywords_matched"] == []


# ---------------------------------------------------------------------------
# run_probe_async — error path
# ---------------------------------------------------------------------------


def test_run_probe_error_on_target_exception():
    async def failing_target(prompt: str) -> str:  # noqa: ARG001
        raise ConnectionError("mock target unreachable")

    result = asyncio.run(run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, failing_target))
    assert result.outcome == "error"
    assert "error" in result.evidence
    assert "unreachable" in result.evidence["error"]


# ---------------------------------------------------------------------------
# Evidence structure
# ---------------------------------------------------------------------------


def test_probe_evidence_contains_prompt_and_path():
    result = asyncio.run(run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, mock_target))
    ev = result.evidence
    assert "prompt_sent" in ev
    assert "trifecta_path" in ev
    assert "rpd_node" in ev
    assert "suc_node" in ev
    assert "exf_node" in ev
    assert "finding_confidence" in ev
    # Path nodes must appear in the prompt
    assert "steal_credentials" in ev["prompt_sent"]


def test_probe_evidence_records_response():
    result = asyncio.run(run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, mock_target))
    assert "response" in result.evidence
    assert result.evidence["response"]


# ---------------------------------------------------------------------------
# ProbeResult immutability — deferred is always True for stub
# ---------------------------------------------------------------------------


def test_probe_result_deferred_always_true():
    """Full exploitation is labelled deferred per ARD §1 non-goals."""
    result = asyncio.run(run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, mock_target))
    assert result.deferred is True


def test_probe_result_ran_at_is_utc():
    result = asyncio.run(run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, mock_target))
    assert result.ran_at.tzinfo is not None


# ---------------------------------------------------------------------------
# schedule_confirm — async task wrapper
# ---------------------------------------------------------------------------


def test_schedule_confirm_returns_task_with_probe_result():
    async def _run():
        task = await schedule_confirm(SAMPLE_FINDING)
        assert asyncio.isfuture(task) or isinstance(task, asyncio.Task)
        result = await task
        assert isinstance(result, ProbeResult)
        assert result.outcome in {"confirmed", "denied", "error"}

    asyncio.run(_run())


def test_schedule_confirm_uses_custom_target():
    async def custom_target(prompt: str) -> str:  # noqa: ARG001
        return "nothing relevant here"

    async def _run():
        task = await schedule_confirm(SAMPLE_FINDING, target=custom_target)
        result = await task
        assert result.outcome == "denied"

    asyncio.run(_run())


def test_schedule_confirm_default_target_confirms():
    async def _run():
        task = await schedule_confirm(SAMPLE_FINDING)
        result = await task
        # Default mock_target returns exploitable content
        assert result.outcome == "confirmed"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Integration — requires Postgres with V6 migration applied
# ---------------------------------------------------------------------------

_TEST_DSN = os.environ.get("DATABASE_URL", "")


@pytest.fixture()
def db_conn():
    if not _TEST_DSN:
        pytest.skip("DATABASE_URL not set — skipping DB integration test")
    import psycopg2  # type: ignore[import-untyped]

    conn = psycopg2.connect(_TEST_DSN)
    # Ensure V6 table exists (idempotent)
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS dynamic_probe_results (
                id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
                scan_run_id   UUID,
                probe_id      TEXT        NOT NULL,
                label         TEXT        NOT NULL,
                trifecta_path JSONB       NOT NULL DEFAULT '[]'::jsonb,
                outcome       TEXT        NOT NULL
                                          CHECK (outcome IN ('confirmed','denied','error')),
                deferred      BOOLEAN     NOT NULL DEFAULT TRUE,
                evidence      JSONB,
                ran_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        conn.commit()
    yield conn
    # Cleanup rows inserted by this test run
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM dynamic_probe_results WHERE probe_id = %s",
            (CANNED_TRIFECTA_PROBE.probe_id,),
        )
        conn.commit()
    conn.close()


def test_persist_probe_result_roundtrip(db_conn):
    result = asyncio.run(
        run_probe_async(CANNED_TRIFECTA_PROBE, SAMPLE_FINDING, mock_target, scan_run_id=None)
    )
    row_id = persist_probe_result(db_conn, result)
    assert row_id  # non-empty UUID string

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT probe_id, outcome, label, deferred FROM dynamic_probe_results WHERE id = %s",
            (row_id,),
        )
        row = cur.fetchone()

    assert row is not None
    probe_id, outcome, label, deferred = row
    assert probe_id == CANNED_TRIFECTA_PROBE.probe_id
    assert outcome == "confirmed"
    assert label == DEFERRED_LABEL
    assert deferred is True


def test_schedule_confirm_persists_when_conn_provided(db_conn):
    async def _run():
        task = await schedule_confirm(SAMPLE_FINDING, conn=db_conn)
        result = await task
        return result

    result = asyncio.run(_run())
    assert result.outcome == "confirmed"

    # Verify it was written to DB
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM dynamic_probe_results WHERE probe_id = %s AND outcome = 'confirmed'",
            (CANNED_TRIFECTA_PROBE.probe_id,),
        )
        (count,) = cur.fetchone()
    assert count >= 1
