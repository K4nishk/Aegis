-- V7__fix_trifecta_null_index.up.sql
-- Fix NULL fail-safe hole in trifecta partial index (KCH-25).
--
-- The original index (V3) used bare #>> comparisons.  When a JSON path is
-- absent, #>> returns NULL, and NULL <> 'false' evaluates to NULL (not TRUE),
-- silently dropping the node from the index.  For a security scanner this is
-- a false negative — an unknown capability should be treated as risk-present.
--
-- Fix: wrap each path extraction in COALESCE so a missing key maps to
-- 'unknown', which satisfies <> 'false' and keeps the node in the index.

DROP INDEX IF EXISTS idx_tool_graph_nodes_trifecta_risk;

CREATE INDEX IF NOT EXISTS idx_tool_graph_nodes_trifecta_risk
    ON tool_graph_nodes (scan_run_id)
    WHERE
        security_caps IS NOT NULL
        AND COALESCE(security_caps #>> '{reads_private_data,value}',    'unknown') <> 'false'
        AND COALESCE(security_caps #>> '{sees_untrusted_content,value}', 'unknown') <> 'false'
        AND COALESCE(security_caps #>> '{can_exfiltrate,value}',         'unknown') <> 'false';
