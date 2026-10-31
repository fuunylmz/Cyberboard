-- Agent release manifests and immutable upgrade reports.

CREATE TABLE IF NOT EXISTS agent_releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    version TEXT NOT NULL,
    artifact_url TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-fA-F]{64}$'),
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    mandatory BOOLEAN NOT NULL DEFAULT false,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (tenant_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_releases_active_idx
    ON agent_releases (tenant_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS agent_upgrade_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    node_id UUID NOT NULL,
    agent_id TEXT NOT NULL,
    target_version TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    error_code TEXT,
    error_message TEXT,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id)
);

CREATE INDEX IF NOT EXISTS agent_upgrade_results_node_idx
    ON agent_upgrade_results (tenant_id, node_id, reported_at DESC);
