-- Fields required by the admin resource API. These are additive so existing
-- installations can migrate without rewriting tenant-owned rows.

ALTER TABLE plans DROP CONSTRAINT IF EXISTS plans_status_check;
ALTER TABLE plans ADD CONSTRAINT plans_status_check
    CHECK (status IN ('active', 'draft', 'archived'));

ALTER TABLE plans
    ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS price_cents BIGINT NOT NULL DEFAULT 0
        CHECK (price_cents >= 0),
    ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'USD',
    ADD COLUMN IF NOT EXISTS device_limit INTEGER NOT NULL DEFAULT 1
        CHECK (device_limit > 0),
    ADD COLUMN IF NOT EXISTS node_group_ids JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS port INTEGER NOT NULL DEFAULT 443
        CHECK (port BETWEEN 1 AND 65535),
    ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS subscription_token TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_tenant_token_idx
    ON subscriptions (tenant_id, subscription_token)
    WHERE subscription_token IS NOT NULL;
