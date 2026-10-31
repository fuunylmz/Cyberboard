CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    UNIQUE (tenant_id, token_hash),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);
CREATE INDEX sessions_active_token_idx ON sessions (tenant_id, token_hash) WHERE revoked_at IS NULL;
