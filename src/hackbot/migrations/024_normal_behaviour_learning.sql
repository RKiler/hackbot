CREATE TABLE behaviour_runs (
    run_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('CREATED','READY','RUNNING','WAITING_LOGIN','PARTIAL','COMPLETED','BLOCKED','CANCELLED','FAILED')),
    limits_json TEXT NOT NULL,
    selected_identities_json TEXT NOT NULL DEFAULT '[]',
    selected_sessions_json TEXT NOT NULL DEFAULT '[]',
    counts_json TEXT NOT NULL DEFAULT '{}',
    coverage_before_json TEXT NOT NULL DEFAULT '{}',
    coverage_after_json TEXT NOT NULL DEFAULT '{}',
    limitations_json TEXT NOT NULL DEFAULT '[]',
    stop_reason TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0,1)),
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE UNIQUE INDEX behaviour_runs_active ON behaviour_runs(target_id)
    WHERE status IN ('CREATED','READY','RUNNING');
CREATE INDEX behaviour_runs_target ON behaviour_runs(target_id,created_at DESC,run_id DESC);

CREATE TABLE behaviour_observations (
    observation_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    run_id TEXT NOT NULL REFERENCES behaviour_runs(run_id),
    exchange_id TEXT NOT NULL UNIQUE REFERENCES traffic_exchanges(exchange_id),
    identity_id TEXT REFERENCES registry_identities(identity_id),
    session_id TEXT REFERENCES browser_sessions(session_id),
    auth_state TEXT NOT NULL,
    role_ids_json TEXT NOT NULL,
    tenant_ids_json TEXT NOT NULL,
    feature TEXT NOT NULL,
    action TEXT NOT NULL,
    protocol TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    operation_metadata_json TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('OBSERVED_ALLOWED','OBSERVED_DENIED','UNKNOWN')),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    observed_at TEXT NOT NULL
);
CREATE INDEX behaviour_observations_target ON behaviour_observations(target_id,observed_at DESC,observation_id DESC);
CREATE INDEX behaviour_observations_operation ON behaviour_observations(target_id,operation_key,auth_state);

CREATE TABLE behaviour_workflows (
    workflow_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    workflow_key TEXT NOT NULL,
    feature TEXT NOT NULL,
    action TEXT NOT NULL,
    identity_id TEXT,
    tenant_ids_json TEXT NOT NULL,
    operation_keys_json TEXT NOT NULL,
    object_ids_json TEXT NOT NULL,
    exchange_ids_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    result TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    UNIQUE(target_id,workflow_key)
);
CREATE INDEX behaviour_workflows_target ON behaviour_workflows(target_id,last_observed_at DESC);

CREATE TABLE behaviour_expectations (
    expectation_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    role_id TEXT NOT NULL DEFAULT '',
    feature TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    expected_access TEXT NOT NULL CHECK (expected_access IN ('ALLOW','DENY','UNKNOWN')),
    status TEXT NOT NULL CHECK (status='CONFIGURED_EXPECTATION'),
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(target_id,role_id,feature,action)
);

CREATE TABLE behaviour_profiles (
    target_id TEXT PRIMARY KEY REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    run_id TEXT REFERENCES behaviour_runs(run_id),
    profile_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
