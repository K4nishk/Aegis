-- V3__add_security_caps.down.sql
-- Revert V3: drop security_caps column and its partial index.
-- Ref: KCH-9

DROP INDEX IF EXISTS idx_tool_graph_nodes_trifecta_risk;

ALTER TABLE tool_graph_nodes
    DROP COLUMN IF EXISTS security_caps;
