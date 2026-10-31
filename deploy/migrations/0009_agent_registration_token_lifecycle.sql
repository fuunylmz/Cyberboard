-- Registration token lifecycle metadata. The clear-text token is never stored.
ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS agent_registration_token_created_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS agent_registration_token_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS agent_registration_token_revoked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS nodes_agent_registration_token_expiry_idx
    ON nodes (tenant_id, agent_registration_token_expires_at)
    WHERE agent_registration_token_hash IS NOT NULL;
