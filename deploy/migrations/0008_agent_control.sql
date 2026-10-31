-- Persistent Agent identity, heartbeat state, and usage receipt boundary.

ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS agent_id TEXT,
    ADD COLUMN IF NOT EXISTS agent_registration_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS agent_public_key TEXT,
    ADD COLUMN IF NOT EXISTS agent_platform TEXT,
    ADD COLUMN IF NOT EXISTS agent_architecture TEXT,
    ADD COLUMN IF NOT EXISTS agent_core_state TEXT,
    ADD COLUMN IF NOT EXISTS agent_memory_bytes BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS agent_disk_free_bytes BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS agent_cpu_percent DOUBLE PRECISION NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS nodes_agent_registration_token_idx
    ON nodes (tenant_id, agent_registration_token_hash)
    WHERE agent_registration_token_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS nodes_agent_id_idx
    ON nodes (tenant_id, agent_id)
    WHERE agent_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS agent_usage_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    node_id UUID NOT NULL,
    agent_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    usage_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, agent_id, batch_id),
    UNIQUE (tenant_id, agent_id, sequence),
    FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id),
    CHECK (window_start < window_end)
);

CREATE INDEX IF NOT EXISTS agent_usage_receipts_tenant_window_idx
    ON agent_usage_receipts (tenant_id, window_start, window_end);
