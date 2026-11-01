ALTER TABLE nodes
    ADD COLUMN applied_config_revision UUID,
    ADD COLUMN applied_generation BIGINT,
    ADD COLUMN applied_at TIMESTAMPTZ;

ALTER TABLE nodes
    ADD CONSTRAINT nodes_applied_config_revision_fk
    FOREIGN KEY (tenant_id, applied_config_revision)
    REFERENCES config_revisions(tenant_id, id);

ALTER TABLE config_revisions ADD COLUMN rollback_of UUID;
ALTER TABLE config_revisions
    ADD CONSTRAINT config_revisions_rollback_of_fk
    FOREIGN KEY (tenant_id, rollback_of) REFERENCES config_revisions(tenant_id, id);

ALTER TABLE config_deployments
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'publish' CHECK (kind IN ('publish', 'rollback')),
    ADD COLUMN actor_user_id UUID,
    ADD COLUMN error_message TEXT,
    ADD COLUMN previous_hash TEXT,
    ADD COLUMN applied_hash TEXT,
    ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN reported_at TIMESTAMPTZ;

CREATE INDEX config_deployments_revision_created_idx
    ON config_deployments (tenant_id, config_revision_id, created_at DESC);
