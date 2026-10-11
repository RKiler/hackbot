ALTER TABLE plan_object_requirements ADD COLUMN test_object_id TEXT REFERENCES test_objects(test_object_id);

CREATE TABLE authorization_hunts (
    hunt_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('MANUAL','PLAN_ONLY','BOUNDED_AUTONOMOUS')),
    status TEXT NOT NULL CHECK (status IN
        ('CREATED','PROFILING','GENERATING','READY','RUNNING','PAUSED','COMPLETED','BLOCKED','CANCELLED')),
    candidate_limit INTEGER NOT NULL CHECK (candidate_limit BETWEEN 1 AND 50),
    request_budget INTEGER NOT NULL CHECK (request_budget BETWEEN 0 AND 50),
    reason_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX authorization_hunts_target_time ON authorization_hunts(target_id,created_at DESC,hunt_id DESC);

CREATE TABLE authorization_candidates (
    candidate_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    hunt_id TEXT NOT NULL REFERENCES authorization_hunts(hunt_id),
    dedupe_key TEXT NOT NULL,
    boundary TEXT NOT NULL CHECK (boundary IN
        ('CROSS_TENANT','HORIZONTAL','VERTICAL','HIDDEN_FUNCTION','ANONYMOUS','GRAPHQL_OBJECT','GRAPHQL_MUTATION','SAME_USER','PARENT_CHILD')),
    owner_identity_id TEXT NOT NULL REFERENCES registry_identities(identity_id),
    boundary_identity_id TEXT REFERENCES registry_identities(identity_id),
    test_object_id TEXT NOT NULL REFERENCES test_objects(test_object_id),
    owner_exchange_id TEXT NOT NULL REFERENCES traffic_exchanges(exchange_id),
    operation_key TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    reasons_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('CANDIDATE','NEEDS_OBJECT','NEEDS_TEMPLATE','NEEDS_SESSION','NEEDS_MANUAL_REVIEW','READY','PLANNED','RUNNING','VALIDATED','REJECTED','BLOCKED')),
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    plan_id TEXT REFERENCES skill_plans(plan_id),
    run_id TEXT REFERENCES plan_runs(run_id),
    validation_id TEXT REFERENCES validations(validation_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(target_id,dedupe_key)
);
CREATE INDEX authorization_candidates_target_score ON authorization_candidates(target_id,score DESC,candidate_id);
CREATE INDEX authorization_candidates_hunt_score ON authorization_candidates(hunt_id,score DESC,candidate_id);

CREATE TABLE authorization_hunt_candidates (
    hunt_id TEXT NOT NULL REFERENCES authorization_hunts(hunt_id),
    candidate_id TEXT NOT NULL REFERENCES authorization_candidates(candidate_id),
    linked_at TEXT NOT NULL,
    PRIMARY KEY(hunt_id,candidate_id)
);
CREATE INDEX authorization_hunt_candidates_candidate ON authorization_hunt_candidates(candidate_id,hunt_id);

CREATE TABLE authorization_observations (
    observation_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    candidate_id TEXT REFERENCES authorization_candidates(candidate_id),
    identity_id TEXT REFERENCES registry_identities(identity_id),
    principal_id TEXT REFERENCES registry_principals(principal_id),
    tenant_id TEXT REFERENCES registry_tenants(tenant_id),
    role_id TEXT REFERENCES registry_roles(role_id),
    test_object_id TEXT REFERENCES test_objects(test_object_id),
    operation_key TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN
        ('OBSERVED_ALLOWED','OBSERVED_DENIED','NOT_OBSERVED','UNKNOWN','AUTH_REQUIRED','NOT_FOUND','ERROR','AMBIGUOUS')),
    exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    evidence_ids_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(target_id,exchange_id,operation_key)
);
CREATE INDEX authorization_observations_target_time ON authorization_observations(target_id,observed_at DESC,observation_id DESC);
CREATE INDEX authorization_observations_candidate_time ON authorization_observations(candidate_id,observed_at DESC);

CREATE TABLE authorization_hunt_objects (
    hunt_id TEXT NOT NULL REFERENCES authorization_hunts(hunt_id),
    test_object_id TEXT NOT NULL UNIQUE REFERENCES test_objects(test_object_id),
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    cleanup_outcome TEXT,
    linked_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(hunt_id,test_object_id)
);
CREATE INDEX authorization_hunt_objects_target ON authorization_hunt_objects(target_id,hunt_id);
