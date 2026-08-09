-- V1__initial_schema.up.sql
-- Aegis DDL: scan_runs, tool_graph_nodes, tool_graph_edges, findings, ai_bom,
-- append-only audit_log (monthly RANGE partitions, BRIN on ts).
-- Ref: ARD §4 / KCH-6

-- ---------------------------------------------------------------------------
-- App role (idempotent guard; role may be pre-created by infra)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        CREATE ROLE aegis_app LOGIN;
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- scan_runs
-- ---------------------------------------------------------------------------
CREATE TABLE scan_runs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status      TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','running','completed','failed')),
    target      TEXT        NOT NULL,
    metadata    JSONB
);

-- ---------------------------------------------------------------------------
-- tool_graph_nodes
--   Trifecta booleans: is_sandboxed, is_auditable, is_pinned
--   caps JSONB: tool capability list (e.g. ["read_fs","network","spawn_proc"])
-- ---------------------------------------------------------------------------
CREATE TABLE tool_graph_nodes (
    id           UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id  UUID    NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    node_key     TEXT    NOT NULL,
    tool_name    TEXT    NOT NULL,
    tool_version TEXT,
    -- trifecta security booleans
    is_sandboxed  BOOLEAN NOT NULL DEFAULT FALSE,
    is_auditable  BOOLEAN NOT NULL DEFAULT FALSE,
    is_pinned     BOOLEAN NOT NULL DEFAULT FALSE,
    -- capabilities: JSONB array of capability strings
    caps          JSONB   NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (scan_run_id, node_key)
);

-- Partial index: quickly find nodes where all trifecta conditions are satisfied
CREATE INDEX idx_tool_graph_nodes_trifecta_all
    ON tool_graph_nodes (scan_run_id)
    WHERE is_sandboxed AND is_auditable AND is_pinned;

-- GIN index on caps for containment/existence queries (@>, ?, ?|, ?&)
CREATE INDEX idx_tool_graph_nodes_caps_gin
    ON tool_graph_nodes USING GIN (caps);

-- ---------------------------------------------------------------------------
-- tool_graph_edges
-- ---------------------------------------------------------------------------
CREATE TABLE tool_graph_edges (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id    UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    source_node_id UUID NOT NULL REFERENCES tool_graph_nodes(id) ON DELETE CASCADE,
    target_node_id UUID NOT NULL REFERENCES tool_graph_nodes(id) ON DELETE CASCADE,
    edge_type      TEXT NOT NULL DEFAULT 'calls',
    metadata       JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tool_graph_edges_scan_run
    ON tool_graph_edges (scan_run_id);
CREATE INDEX idx_tool_graph_edges_source
    ON tool_graph_edges (source_node_id);
CREATE INDEX idx_tool_graph_edges_target
    ON tool_graph_edges (target_node_id);

-- ---------------------------------------------------------------------------
-- findings
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id  UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    node_id      UUID REFERENCES tool_graph_nodes(id) ON DELETE SET NULL,
    severity     TEXT NOT NULL
                 CHECK (severity IN ('critical','high','medium','low','info')),
    rule_id      TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT,
    evidence     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_run ON findings (scan_run_id);
CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_node     ON findings (node_id) WHERE node_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- ai_bom  (AI Bill of Materials)
-- ---------------------------------------------------------------------------
CREATE TABLE ai_bom (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id       UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    component_name    TEXT NOT NULL,
    component_version TEXT,
    component_type    TEXT NOT NULL
                      CHECK (component_type IN ('model','library','tool','plugin','other')),
    purl              TEXT,           -- Package URL (https://github.com/package-url/purl-spec)
    checksum          TEXT,
    metadata          JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ai_bom_scan_run ON ai_bom (scan_run_id);
CREATE INDEX idx_ai_bom_component_name ON ai_bom (component_name);

-- ---------------------------------------------------------------------------
-- audit_log  (append-only, monthly RANGE partitions, BRIN on ts)
-- Parent table: no rows live here — all rows go to child partitions.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id            UUID        NOT NULL DEFAULT gen_random_uuid(),
    ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor         TEXT        NOT NULL,
    action        TEXT        NOT NULL,
    resource_type TEXT        NOT NULL,
    resource_id   UUID,
    old_val       JSONB,
    new_val       JSONB,
    PRIMARY KEY (id, ts)        -- partition key must be part of PK
) PARTITION BY RANGE (ts);

-- BRIN index on ts: extremely compact for append-only time-ordered data
CREATE INDEX idx_audit_log_ts_brin
    ON audit_log USING BRIN (ts);

-- Monthly partitions: 2025-01 through 2027-12 (36 months)
-- 2025
CREATE TABLE audit_log_2025_01 PARTITION OF audit_log FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE audit_log_2025_02 PARTITION OF audit_log FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE audit_log_2025_03 PARTITION OF audit_log FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE audit_log_2025_04 PARTITION OF audit_log FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE audit_log_2025_05 PARTITION OF audit_log FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE audit_log_2025_06 PARTITION OF audit_log FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE audit_log_2025_07 PARTITION OF audit_log FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE audit_log_2025_08 PARTITION OF audit_log FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE audit_log_2025_09 PARTITION OF audit_log FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE audit_log_2025_10 PARTITION OF audit_log FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE audit_log_2025_11 PARTITION OF audit_log FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE audit_log_2025_12 PARTITION OF audit_log FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');
-- 2026
CREATE TABLE audit_log_2026_01 PARTITION OF audit_log FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE audit_log_2026_02 PARTITION OF audit_log FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit_log_2026_03 PARTITION OF audit_log FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE audit_log_2026_04 PARTITION OF audit_log FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE audit_log_2026_05 PARTITION OF audit_log FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_log_2026_06 PARTITION OF audit_log FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE audit_log_2026_07 PARTITION OF audit_log FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE audit_log_2026_08 PARTITION OF audit_log FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE audit_log_2026_09 PARTITION OF audit_log FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE audit_log_2026_10 PARTITION OF audit_log FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE audit_log_2026_11 PARTITION OF audit_log FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE audit_log_2026_12 PARTITION OF audit_log FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
-- 2027
CREATE TABLE audit_log_2027_01 PARTITION OF audit_log FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE audit_log_2027_02 PARTITION OF audit_log FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE audit_log_2027_03 PARTITION OF audit_log FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');
CREATE TABLE audit_log_2027_04 PARTITION OF audit_log FOR VALUES FROM ('2027-04-01') TO ('2027-05-01');
CREATE TABLE audit_log_2027_05 PARTITION OF audit_log FOR VALUES FROM ('2027-05-01') TO ('2027-06-01');
CREATE TABLE audit_log_2027_06 PARTITION OF audit_log FOR VALUES FROM ('2027-06-01') TO ('2027-07-01');
CREATE TABLE audit_log_2027_07 PARTITION OF audit_log FOR VALUES FROM ('2027-07-01') TO ('2027-08-01');
CREATE TABLE audit_log_2027_08 PARTITION OF audit_log FOR VALUES FROM ('2027-08-01') TO ('2027-09-01');
CREATE TABLE audit_log_2027_09 PARTITION OF audit_log FOR VALUES FROM ('2027-09-01') TO ('2027-10-01');
CREATE TABLE audit_log_2027_10 PARTITION OF audit_log FOR VALUES FROM ('2027-10-01') TO ('2027-11-01');
CREATE TABLE audit_log_2027_11 PARTITION OF audit_log FOR VALUES FROM ('2027-11-01') TO ('2027-12-01');
CREATE TABLE audit_log_2027_12 PARTITION OF audit_log FOR VALUES FROM ('2027-12-01') TO ('2028-01-01');

-- ---------------------------------------------------------------------------
-- Append-only enforcement: revoke mutation privileges from app role
-- ---------------------------------------------------------------------------
REVOKE UPDATE, DELETE ON audit_log FROM aegis_app;
