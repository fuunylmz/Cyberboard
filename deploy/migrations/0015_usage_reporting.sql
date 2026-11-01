ALTER TABLE nodes
    ALTER COLUMN agent_memory_bytes DROP NOT NULL,
    ALTER COLUMN agent_memory_bytes DROP DEFAULT,
    ALTER COLUMN agent_cpu_percent DROP NOT NULL,
    ALTER COLUMN agent_cpu_percent DROP DEFAULT;

UPDATE nodes
SET agent_memory_bytes = NULL
WHERE agent_memory_bytes = 0;

UPDATE nodes
SET agent_cpu_percent = NULL
WHERE agent_cpu_percent = 0;

ALTER TABLE agent_usage_receipts
    ADD COLUMN IF NOT EXISTS payload_version INTEGER NOT NULL DEFAULT 1;
