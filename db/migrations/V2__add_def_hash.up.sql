-- V2__add_def_hash.up.sql
-- Add def_hash column to tool_graph_nodes for rug-pull baseline detection.
-- Ref: ARD §3, §14 / KCH-8

ALTER TABLE tool_graph_nodes
    ADD COLUMN IF NOT EXISTS def_hash TEXT;

-- Index for fast lookup by hash (rug-pull diff queries)
CREATE INDEX IF NOT EXISTS idx_tool_graph_nodes_def_hash
    ON tool_graph_nodes (def_hash)
    WHERE def_hash IS NOT NULL;
