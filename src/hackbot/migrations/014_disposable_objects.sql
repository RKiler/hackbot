CREATE TABLE test_objects (
    test_object_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    object_ref_id TEXT NOT NULL UNIQUE,
    object_type TEXT NOT NULL,
    external_id_hash TEXT,
    external_id_evidence_id TEXT REFERENCES evidence(evidence_id),
    creator_identity_id TEXT NOT NULL REFERENCES registry_identities(identity_id),
    owner_principal_id TEXT,
    tenant_id TEXT NOT NULL REFERENCES registry_tenants(tenant_id),
    parent_test_object_id TEXT REFERENCES test_objects(test_object_id),
    creation_plan_id TEXT,
    creation_run_id TEXT REFERENCES plan_runs(run_id),
    creation_hypothesis_id TEXT,
    creation_action_id TEXT NOT NULL UNIQUE,
    creation_exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    recipe_id TEXT NOT NULL,
    recipe_hash TEXT NOT NULL,
    test_name TEXT NOT NULL,
    lifecycle TEXT NOT NULL CHECK (lifecycle IN (
        'PLANNED','CREATING','CREATED','VERIFYING','READY','IN_USE',
        'CLEANUP_PENDING','CLEANING','CLEANED','ORPHANED','FAILED','UNKNOWN')),
    disposable INTEGER NOT NULL CHECK (disposable IN (0,1)),
    cleanup_required INTEGER NOT NULL CHECK (cleanup_required IN (0,1)),
    cleanup_strategy TEXT NOT NULL CHECK (cleanup_strategy IN (
        'AUTO_CLEANUP','MANUAL_CLEANUP','NO_CLEANUP_REQUIRED','CLEANUP_UNAVAILABLE')),
    pending_action_id TEXT,
    pending_approval_id TEXT,
    setup_requests_reserved INTEGER NOT NULL DEFAULT 0,
    cleanup_requests_reserved INTEGER NOT NULL DEFAULT 0,
    creation_evidence_json TEXT NOT NULL DEFAULT '[]',
    verification_evidence_json TEXT NOT NULL DEFAULT '[]',
    cleanup_evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    verified_at TEXT,
    cleaned_at TEXT,
    last_checked_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX test_objects_target_state ON test_objects(target_id,lifecycle,created_at DESC);
CREATE INDEX test_objects_target_tenant ON test_objects(target_id,tenant_id,object_type,lifecycle);
CREATE INDEX test_objects_target_creator ON test_objects(target_id,creator_identity_id,created_at DESC);
CREATE INDEX test_objects_target_type ON test_objects(target_id,object_type,created_at DESC);
CREATE INDEX test_objects_plan ON test_objects(creation_plan_id,created_at DESC);
CREATE INDEX test_objects_run ON test_objects(creation_run_id,created_at DESC);
CREATE INDEX test_objects_cleanup ON test_objects(cleanup_required,lifecycle,updated_at);
CREATE INDEX test_objects_hash ON test_objects(target_id,external_id_hash);

CREATE TABLE test_object_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_object_id TEXT NOT NULL REFERENCES test_objects(test_object_id),
    event_type TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    source TEXT NOT NULL,
    action_id TEXT,
    exchange_id TEXT,
    evidence_ids_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX test_object_events_object ON test_object_events(test_object_id,event_id DESC);
CREATE TRIGGER test_object_events_no_update BEFORE UPDATE ON test_object_events
BEGIN SELECT RAISE(ABORT,'object events are immutable'); END;
CREATE TRIGGER test_object_events_no_delete BEFORE DELETE ON test_object_events
BEGIN SELECT RAISE(ABORT,'object events are immutable'); END;

CREATE TABLE test_object_reservations (
    reservation_id TEXT PRIMARY KEY,
    test_object_id TEXT NOT NULL REFERENCES test_objects(test_object_id),
    holder_run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','RELEASED','EXPIRED')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    released_at TEXT
);
CREATE UNIQUE INDEX test_object_one_active_reservation ON test_object_reservations(test_object_id)
    WHERE status='ACTIVE';
CREATE INDEX test_object_reservations_run ON test_object_reservations(holder_run_id,status);
CREATE INDEX test_object_reservations_expiry ON test_object_reservations(status,expires_at);

CREATE TABLE test_object_operations (
    action_id TEXT PRIMARY KEY,
    test_object_id TEXT NOT NULL REFERENCES test_objects(test_object_id),
    operation_kind TEXT NOT NULL CHECK (operation_kind IN ('CREATE','VERIFY','UPDATE','CLEANUP','VERIFY_CLEANUP')),
    execution_id TEXT UNIQUE,
    exchange_id TEXT,
    decision_id TEXT,
    permit_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVAL_REQUIRED','DISPATCHING',
                                          'SUCCEEDED','DENIED','FAILED','AMBIGUOUS')),
    reason_code TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX test_object_operations_object ON test_object_operations(test_object_id,created_at DESC);

CREATE TABLE plan_object_requirements (
    requirement_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES skill_plans(plan_id),
    target_id TEXT NOT NULL,
    object_type TEXT NOT NULL,
    recipe_id TEXT NOT NULL,
    creator_identity_id TEXT NOT NULL REFERENCES registry_identities(identity_id),
    tenant_id TEXT NOT NULL REFERENCES registry_tenants(tenant_id),
    parent_test_object_id TEXT REFERENCES test_objects(test_object_id),
    created_at TEXT NOT NULL,
    UNIQUE(plan_id,object_type,creator_identity_id,tenant_id,parent_test_object_id)
);
CREATE INDEX plan_object_requirements_target ON plan_object_requirements(target_id,plan_id);
