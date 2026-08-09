-- V7__fix_trifecta_null_index.down.sql
-- Restore the original (nullable) index definition from V3 (KCH-25 rollback).
-- WARNING: restoring this index re-introduces the NULL false-negative hole.

DROP INDEX IF EXISTS idx_tool_graph_nodes_trifecta_risk;

CREATE INDEX IF NOT EXISTS idx_tool_graph_nodes_trifecta_risk
    ON tool_graph_nodes (scan_run_id)
    WHERE
        security_caps IS NOT NULL
        AND (security_caps #>> '{reads_private_data,value}')    <> 'false'
        AND (security_caps #>> '{sees_untrusted_content,value}') <> 'false'
        AND (security_caps #>> '{can_exfiltrate,value}')         <> 'false';
