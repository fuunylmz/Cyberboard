CREATE TABLE subscription_nodes (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    subscription_id UUID NOT NULL,
    node_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subscription_id, node_id),
    FOREIGN KEY (tenant_id, subscription_id) REFERENCES subscriptions(tenant_id, id),
    FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id)
);
