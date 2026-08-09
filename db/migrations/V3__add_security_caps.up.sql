-- V3__add_security_caps.up.sql
-- Add security_caps JSONB column to tool_graph_nodes for KCH-9 trifecta tagging.
-- Stores per-tool SecurityProfile as {"reads_private_data": {...},
-- "sees_untrusted_content": {...}, "can_exfiltrate": {...}}.
-- Ref: ARD §0 thesis, §14 trifecta rule / KCH-9

ALTER TABLE tool_graph_nodes
    ADD COLUMN IF NOT EXISTS security_caps JSONB;

-- Partial index: quickly find nodes where ALL three trifecta caps are risk-present
-- (value is JSON boolean true or the string "unknown"; anything that is not false).
-- Used by trifecta-path queries to avoid full-table scans.
CREATE INDEX IF NOT EXISTS idx_tool_graph_nodes_trifecta_risk
    ON tool_graph_nodes (scan_run_id)
    WHERE
        security_caps IS NOT NULL
        AND (security_caps #>> '{reads_private_data,value}')    <> 'false'
        AND (security_caps #>> '{sees_untrusted_content,value}') <> 'false'
        AND (security_caps #>> '{can_exfiltrate,value}')         <> 'false';
