-- Versioned subscription token rotation. Clear text remains for the current
-- portal display contract; validation uses the hash whenever it is present.
ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS subscription_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS subscription_token_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS subscription_token_revoked_at TIMESTAMPTZ;

UPDATE subscriptions
SET subscription_token_hash = encode(digest(subscription_token, 'sha256'), 'hex')
WHERE subscription_token IS NOT NULL AND subscription_token_hash IS NULL;

CREATE INDEX IF NOT EXISTS subscriptions_tenant_token_hash_idx
    ON subscriptions (tenant_id, subscription_token_hash)
    WHERE subscription_token_hash IS NOT NULL;
