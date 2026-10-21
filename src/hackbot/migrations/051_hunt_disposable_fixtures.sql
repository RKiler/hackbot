CREATE TABLE hunt_fixtures (
    hunt_id TEXT NOT NULL REFERENCES hunt_runs(hunt_id),
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    identity_id TEXT NOT NULL REFERENCES registry_identities(identity_id),
    tenant_id TEXT NOT NULL REFERENCES registry_tenants(tenant_id),
    object_type TEXT NOT NULL,
    test_object_id TEXT NOT NULL UNIQUE REFERENCES test_objects(test_object_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (hunt_id, tenant_id, object_type)
);
CREATE INDEX hunt_fixtures_target ON hunt_fixtures(target_id, hunt_id);
