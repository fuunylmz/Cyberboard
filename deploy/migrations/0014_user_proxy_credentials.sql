-- Stable per-user proxy credentials. Rotation is deliberately explicit: the
-- portal subscription-token rotation transaction replaces this row, while all
-- other paths use INSERT ... ON CONFLICT DO NOTHING and keep existing values.
CREATE TABLE user_proxy_credentials (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID NOT NULL,
    password TEXT NOT NULL,
    uuid UUID NOT NULL,
    shadowsocks_2022_key_128 TEXT NOT NULL,
    shadowsocks_2022_key_256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id),
    UNIQUE (tenant_id, uuid),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);
