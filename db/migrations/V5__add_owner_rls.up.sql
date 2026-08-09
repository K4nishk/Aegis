-- V5__add_owner_rls.up.sql
-- KCH-17: Add owner_id to scan_runs + enable RLS on all user-data tables.
-- Defense in two layers:
--   1. DB layer: RLS policy uses current_setting('app.user_id') — DB refuses rows the user doesn't own.
--   2. API layer: every query filters by owner_id (routes.py).
-- Ref: ARD §6.1 SEC-1, §6.2

-- ---------------------------------------------------------------------------
-- owner_id on scan_runs (the root ownership anchor)
-- ---------------------------------------------------------------------------
ALTER TABLE scan_runs
    ADD COLUMN IF NOT EXISTS owner_id UUID NOT NULL
        DEFAULT '00000000-0000-0000-0000-000000000001';

CREATE INDEX IF NOT EXISTS idx_scan_runs_owner_id
    ON scan_runs (owner_id);

-- ---------------------------------------------------------------------------
-- Row-Level Security: scan_runs
-- FORCE applies RLS even to the table owner / superuser role.
-- ---------------------------------------------------------------------------
ALTER TABLE scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_runs FORCE ROW LEVEL SECURITY;

-- Ownership isolation policy: only rows whose owner_id matches the session user.
-- nullif(..., '') guards against the setting being absent (returns NULL → no rows visible,
-- which is the secure default: unauthenticated sessions see nothing).
CREATE POLICY scan_runs_owner_isolation ON scan_runs
    USING (
        owner_id = nullif(current_setting('app.user_id', true), '')::uuid
    );

-- ---------------------------------------------------------------------------
-- RLS: tool_graph_nodes (child of scan_runs via scan_run_id FK)
-- Policy delegates to scan_runs ownership.
-- ---------------------------------------------------------------------------
ALTER TABLE tool_graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_graph_nodes FORCE ROW LEVEL SECURITY;

CREATE POLICY tool_graph_nodes_owner_isolation ON tool_graph_nodes
    USING (
        scan_run_id IN (
            SELECT id FROM scan_runs
            WHERE owner_id = nullif(current_setting('app.user_id', true), '')::uuid
        )
    );

-- ---------------------------------------------------------------------------
-- RLS: tool_graph_edges
-- ---------------------------------------------------------------------------
ALTER TABLE tool_graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_graph_edges FORCE ROW LEVEL SECURITY;

CREATE POLICY tool_graph_edges_owner_isolation ON tool_graph_edges
    USING (
        scan_run_id IN (
            SELECT id FROM scan_runs
            WHERE owner_id = nullif(current_setting('app.user_id', true), '')::uuid
        )
    );

-- ---------------------------------------------------------------------------
-- RLS: findings
-- ---------------------------------------------------------------------------
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;

CREATE POLICY findings_owner_isolation ON findings
    USING (
        scan_run_id IN (
            SELECT id FROM scan_runs
            WHERE owner_id = nullif(current_setting('app.user_id', true), '')::uuid
        )
    );

-- ---------------------------------------------------------------------------
-- RLS: ai_bom
-- ---------------------------------------------------------------------------
ALTER TABLE ai_bom ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_bom FORCE ROW LEVEL SECURITY;

CREATE POLICY ai_bom_owner_isolation ON ai_bom
    USING (
        scan_run_id IN (
            SELECT id FROM scan_runs
            WHERE owner_id = nullif(current_setting('app.user_id', true), '')::uuid
        )
    );

-- ---------------------------------------------------------------------------
-- Grants for aegis_app role (non-superuser; subject to RLS).
-- The app should connect as aegis_app in production so RLS is enforced.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON scan_runs TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON tool_graph_nodes TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON tool_graph_edges TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON findings TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON ai_bom TO aegis_app;
