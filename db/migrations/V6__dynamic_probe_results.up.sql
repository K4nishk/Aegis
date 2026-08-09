-- V6__dynamic_probe_results.up.sql
-- Stores outcomes of dynamic-confirm probe runs (KCH-15).
-- One row per probe execution; deferred=TRUE marks stubs / un-run batteries.

CREATE TABLE IF NOT EXISTS dynamic_probe_results (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID        REFERENCES scan_runs(id) ON DELETE CASCADE,
    probe_id      TEXT        NOT NULL,
    label         TEXT        NOT NULL,
    trifecta_path JSONB       NOT NULL DEFAULT '[]'::jsonb,
    outcome       TEXT        NOT NULL
                              CHECK (outcome IN ('confirmed', 'denied', 'error')),
    deferred      BOOLEAN     NOT NULL DEFAULT TRUE,
    evidence      JSONB,
    ran_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dynamic_probe_results_scan_run
    ON dynamic_probe_results (scan_run_id)
    WHERE scan_run_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_dynamic_probe_results_outcome
    ON dynamic_probe_results (outcome);
