-- Rotating refresh credentials for short-lived access sessions.
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS refresh_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS refresh_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS refresh_rotated_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS sessions_refresh_token_idx
    ON sessions (tenant_id, refresh_token_hash)
    WHERE refresh_token_hash IS NOT NULL;
