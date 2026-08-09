-- V4__add_server_name.up.sql
-- Restore server_name column to tool_graph_nodes so it is persisted explicitly
-- rather than derived by splitting node_key (which is ambiguous when server_name=""
-- and when a tool name contains "/").
-- Ref: KCH-24

ALTER TABLE tool_graph_nodes
    ADD COLUMN IF NOT EXISTS server_name TEXT NOT NULL DEFAULT '';

-- Index for "which tools does server X provide?" queries
CREATE INDEX IF NOT EXISTS idx_tool_graph_nodes_server_name
    ON tool_graph_nodes (server_name)
    WHERE server_name <> '';
