-- V2__add_def_hash.down.sql
-- Remove def_hash column and its index from tool_graph_nodes.
-- Ref: KCH-8

DROP INDEX IF EXISTS idx_tool_graph_nodes_def_hash;

ALTER TABLE tool_graph_nodes
    DROP COLUMN IF EXISTS def_hash;
