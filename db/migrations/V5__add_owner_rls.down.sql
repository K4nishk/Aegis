-- V5__add_owner_rls.down.sql
-- Rollback: remove RLS policies, disable RLS, drop owner_id from scan_runs.

-- ai_bom
DROP POLICY IF EXISTS ai_bom_owner_isolation ON ai_bom;
ALTER TABLE ai_bom DISABLE ROW LEVEL SECURITY;

-- findings
DROP POLICY IF EXISTS findings_owner_isolation ON findings;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;

-- tool_graph_edges
DROP POLICY IF EXISTS tool_graph_edges_owner_isolation ON tool_graph_edges;
ALTER TABLE tool_graph_edges DISABLE ROW LEVEL SECURITY;

-- tool_graph_nodes
DROP POLICY IF EXISTS tool_graph_nodes_owner_isolation ON tool_graph_nodes;
ALTER TABLE tool_graph_nodes DISABLE ROW LEVEL SECURITY;

-- scan_runs
DROP POLICY IF EXISTS scan_runs_owner_isolation ON scan_runs;
ALTER TABLE scan_runs DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS idx_scan_runs_owner_id;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS owner_id;
