-- V1__initial_schema.down.sql
-- Reverses V1__initial_schema.up.sql.
-- Drop order respects FK constraints (children before parents).
-- Ref: ARD §4 / KCH-6

-- audit_log partitions are dropped automatically with the parent
DROP TABLE IF EXISTS audit_log CASCADE;

DROP TABLE IF EXISTS findings     CASCADE;
DROP TABLE IF EXISTS ai_bom       CASCADE;
DROP TABLE IF EXISTS tool_graph_edges CASCADE;
DROP TABLE IF EXISTS tool_graph_nodes CASCADE;
DROP TABLE IF EXISTS scan_runs    CASCADE;

-- Leave aegis_app role in place: role lifecycle is managed by infra, not DDL.
