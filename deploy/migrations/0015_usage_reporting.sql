ALTER TABLE agent_usage_receipts
    ADD COLUMN IF NOT EXISTS payload_version INTEGER NOT NULL DEFAULT 1;
