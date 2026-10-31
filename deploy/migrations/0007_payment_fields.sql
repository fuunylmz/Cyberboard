-- Payment lifecycle fields. All keys are tenant scoped and webhook events are idempotent.
ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
    ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS provider_payment_id TEXT,
    ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS orders_tenant_user_idempotency_idx
    ON orders (tenant_id, user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

ALTER TABLE payments
    ADD COLUMN IF NOT EXISTS provider_event_id TEXT,
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS payments_tenant_provider_event_idx
    ON payments (tenant_id, provider, provider_event_id)
    WHERE provider_event_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS payments_tenant_idempotency_idx
    ON payments (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
