CREATE TABLE registry_targets (
    target_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL UNIQUE,
    registered_at TEXT NOT NULL
);

CREATE TABLE registry_principals (
    principal_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    label TEXT NOT NULL,
    external_user_id TEXT,
    observation_state TEXT NOT NULL CHECK (observation_state IN ('CONFIGURED','OBSERVED','INFERRED')),
    evidence_ids_json TEXT NOT NULL,
    source_provider TEXT,
    source_entity TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (target_id, principal_id)
);

CREATE TABLE registry_tenants (
    tenant_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    observation_state TEXT NOT NULL CHECK (observation_state IN ('CONFIGURED','OBSERVED','INFERRED')),
    evidence_ids_json TEXT NOT NULL,
    source_provider TEXT,
    source_entity TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (target_id, tenant_id),
    UNIQUE (target_id, label)
);

CREATE TABLE registry_roles (
    role_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    name TEXT NOT NULL,
    observation_state TEXT NOT NULL CHECK (observation_state IN ('CONFIGURED','OBSERVED','INFERRED')),
    evidence_ids_json TEXT NOT NULL,
    source_provider TEXT,
    source_entity TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (target_id, role_id),
    UNIQUE (target_id, name)
);

CREATE TABLE registry_identities (
    identity_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    alias TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','DISABLED','PENDING','REAUTH_REQUIRED','UNKNOWN')),
    account_source TEXT NOT NULL CHECK (account_source IN (
        'RESEARCHER_PROVIDED','PROGRAM_PROVIDED','PROGRAM_APPROVED_CREATED','IMPORTED_SESSION','UNKNOWN')),
    principal_id TEXT,
    principal_state TEXT,
    principal_fact_id TEXT REFERENCES facts(fact_id),
    secret_ref TEXT,
    observation_state TEXT NOT NULL CHECK (observation_state IN ('CONFIGURED','OBSERVED','INFERRED')),
    evidence_ids_json TEXT NOT NULL,
    source_provider TEXT,
    source_entity TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (target_id, identity_id),
    UNIQUE (target_id, alias),
    FOREIGN KEY (target_id, principal_id) REFERENCES registry_principals(target_id, principal_id),
    CHECK ((principal_id IS NULL AND principal_state IS NULL AND principal_fact_id IS NULL)
        OR (principal_id IS NOT NULL AND principal_state IN ('CONFIGURED','OBSERVED','INFERRED')))
);

CREATE INDEX registry_identities_target_alias_idx ON registry_identities(target_id, alias, identity_id);
CREATE INDEX registry_identities_target_principal_idx ON registry_identities(target_id, principal_id, alias);

CREATE TABLE registry_principal_links (
    link_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    identity_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    observation_state TEXT NOT NULL CHECK (observation_state IN ('CONFIGURED','OBSERVED','INFERRED')),
    evidence_ids_json TEXT NOT NULL,
    fact_id TEXT REFERENCES facts(fact_id),
    created_at TEXT NOT NULL,
    FOREIGN KEY (target_id, identity_id) REFERENCES registry_identities(target_id, identity_id),
    FOREIGN KEY (target_id, principal_id) REFERENCES registry_principals(target_id, principal_id),
    CHECK ((observation_state='CONFIGURED' AND fact_id IS NULL)
        OR (observation_state!='CONFIGURED' AND fact_id IS NOT NULL))
);

CREATE INDEX registry_principal_links_identity_idx
    ON registry_principal_links(identity_id, created_at, link_id);
CREATE UNIQUE INDEX registry_principal_links_configured_idx
    ON registry_principal_links(identity_id, principal_id) WHERE observation_state='CONFIGURED';
CREATE UNIQUE INDEX registry_principal_links_observed_fact_idx
    ON registry_principal_links(identity_id, principal_id, observation_state, fact_id)
    WHERE observation_state!='CONFIGURED';
CREATE TRIGGER registry_principal_links_no_update BEFORE UPDATE ON registry_principal_links
BEGIN SELECT RAISE(ABORT, 'immutable principal link'); END;
CREATE TRIGGER registry_principal_links_no_delete BEFORE DELETE ON registry_principal_links
BEGIN SELECT RAISE(ABORT, 'immutable principal link'); END;

CREATE TABLE registry_memberships (
    membership_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    identity_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','INACTIVE','PENDING','UNKNOWN')),
    is_primary INTEGER NOT NULL CHECK (is_primary IN (0,1)),
    observation_state TEXT NOT NULL CHECK (observation_state IN ('CONFIGURED','OBSERVED','INFERRED')),
    evidence_ids_json TEXT NOT NULL,
    fact_id TEXT REFERENCES facts(fact_id),
    source_provider TEXT,
    source_entity TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (target_id, membership_id),
    FOREIGN KEY (target_id, identity_id) REFERENCES registry_identities(target_id, identity_id),
    FOREIGN KEY (target_id, tenant_id) REFERENCES registry_tenants(target_id, tenant_id),
    CHECK ((observation_state = 'CONFIGURED' AND fact_id IS NULL)
        OR (observation_state != 'CONFIGURED' AND fact_id IS NOT NULL))
);

CREATE UNIQUE INDEX registry_configured_membership_idx
    ON registry_memberships(identity_id, tenant_id) WHERE observation_state='CONFIGURED';
CREATE UNIQUE INDEX registry_observed_membership_fact_idx
    ON registry_memberships(identity_id, tenant_id, observation_state, fact_id)
    WHERE observation_state!='CONFIGURED';
CREATE UNIQUE INDEX registry_configured_primary_idx
    ON registry_memberships(identity_id) WHERE is_primary=1 AND observation_state='CONFIGURED' AND status!='INACTIVE';
CREATE INDEX registry_memberships_target_tenant_idx
    ON registry_memberships(target_id, tenant_id, observation_state, identity_id);
CREATE INDEX registry_memberships_identity_idx
    ON registry_memberships(identity_id, observation_state, tenant_id);

CREATE TABLE registry_membership_roles (
    target_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (membership_id, role_id),
    FOREIGN KEY (target_id, membership_id) REFERENCES registry_memberships(target_id, membership_id),
    FOREIGN KEY (target_id, role_id) REFERENCES registry_roles(target_id, role_id)
);

CREATE INDEX registry_membership_roles_role_idx ON registry_membership_roles(role_id, membership_id);

CREATE TRIGGER registry_observed_membership_no_update
BEFORE UPDATE ON registry_memberships WHEN OLD.observation_state!='CONFIGURED'
BEGIN SELECT RAISE(ABORT, 'observed membership is immutable'); END;
CREATE TRIGGER registry_observed_membership_no_delete
BEFORE DELETE ON registry_memberships WHEN OLD.observation_state!='CONFIGURED'
BEGIN SELECT RAISE(ABORT, 'observed membership is immutable'); END;
