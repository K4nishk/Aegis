-- V4__add_server_name.down.sql
-- Revert: drop server_name column added in V4 up migration.
-- Ref: KCH-24

DROP INDEX IF EXISTS idx_tool_graph_nodes_server_name;

ALTER TABLE tool_graph_nodes
    DROP COLUMN IF EXISTS server_name;
