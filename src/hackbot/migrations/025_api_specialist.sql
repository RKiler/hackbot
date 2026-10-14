CREATE TABLE api_operations (
    operation_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    version_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    operation_type TEXT NOT NULL CHECK (operation_type IN
        ('REST','GRAPHQL_QUERY','GRAPHQL_MUTATION','GRAPHQL_SUBSCRIPTION','RPC','BULK_API','UNKNOWN')),
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    document_evidence_id TEXT REFERENCES evidence(evidence_id),
    persisted_hash TEXT,
    variables_json TEXT NOT NULL,
    input_types_json TEXT NOT NULL,
    fields_json TEXT NOT NULL,
    feature TEXT NOT NULL,
    identity_ids_json TEXT NOT NULL,
    role_ids_json TEXT NOT NULL,
    tenant_ids_json TEXT NOT NULL,
    exchange_ids_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    source_refs_json TEXT NOT NULL,
    source_asset_hash TEXT,
    state TEXT NOT NULL CHECK (state IN ('CURRENT','STALE')),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(target_id,operation_key,version_hash)
);
CREATE INDEX api_operations_target_state ON api_operations(target_id,state,last_seen DESC,operation_id);
CREATE INDEX api_operations_target_key ON api_operations(target_id,operation_key,state);

CREATE TABLE api_candidates (
    candidate_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    operation_id TEXT NOT NULL REFERENCES api_operations(operation_id),
    category TEXT NOT NULL CHECK (category IN
        ('OBJECT_AUTH','FIELD_AUTH','NESTED_AUTH','MUTATION_AUTH','BFLA','BATCH_AUTH','MASS_ASSIGNMENT_CANDIDATE')),
    boundary_identity_id TEXT REFERENCES registry_identities(identity_id),
    owner_identity_id TEXT REFERENCES registry_identities(identity_id),
    test_object_id TEXT REFERENCES test_objects(test_object_id),
    owner_exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    field_path TEXT,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    reasons_json TEXT NOT NULL,
    gaps_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('CANDIDATE','PLAN_ONLY','READY','PLANNED','RUNNING','VALIDATED','REJECTED','REVIEW','BLOCKED','STALE')),
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    plan_id TEXT REFERENCES skill_plans(plan_id),
    run_id TEXT REFERENCES plan_runs(run_id),
    validation_id TEXT REFERENCES validations(validation_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(target_id,operation_id,category,boundary_identity_id,test_object_id,field_path)
);
CREATE INDEX api_candidates_target_score ON api_candidates(target_id,status,score DESC,candidate_id);
CREATE INDEX api_candidates_operation ON api_candidates(operation_id,status);

CREATE TABLE api_specialist_runs (
    run_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('PLAN_ONLY','BOUNDED_AUTONOMOUS')),
    status TEXT NOT NULL CHECK (status IN ('RUNNING','COMPLETED','PARTIAL','FAILED')),
    counts_json TEXT NOT NULL,
    gaps_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX api_specialist_runs_target ON api_specialist_runs(target_id,created_at DESC,run_id DESC);
