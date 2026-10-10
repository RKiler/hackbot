CREATE TABLE traffic_requests (
    request_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    source TEXT NOT NULL,
    method TEXT NOT NULL,
    principal_id TEXT,
    origin TEXT NOT NULL,
    display_path TEXT NOT NULL,
    path_fingerprint TEXT NOT NULL,
    structural_fingerprint TEXT NOT NULL,
    query_names_json TEXT NOT NULL,
    header_names_json TEXT NOT NULL,
    content_type TEXT,
    http_version TEXT,
    endpoint_id TEXT,
    operation_id TEXT,
    body_evidence_id TEXT REFERENCES evidence(evidence_id),
    observation_evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    body_size INTEGER CHECK (body_size >= 0),
    body_hash TEXT,
    artifact_hash TEXT,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX traffic_requests_target_method_path_idx
    ON traffic_requests(target_id, method, path_fingerprint, observed_at DESC, request_id DESC);
CREATE INDEX traffic_requests_target_fingerprint_idx
    ON traffic_requests(target_id, structural_fingerprint, observed_at DESC, request_id DESC);
CREATE INDEX traffic_requests_target_endpoint_idx
    ON traffic_requests(target_id, endpoint_id, observed_at DESC, request_id DESC);
CREATE INDEX traffic_requests_target_operation_idx
    ON traffic_requests(target_id, operation_id, observed_at DESC, request_id DESC);

CREATE TABLE traffic_responses (
    response_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    request_id TEXT NOT NULL UNIQUE REFERENCES traffic_requests(request_id),
    source TEXT NOT NULL,
    status_code INTEGER CHECK (status_code BETWEEN 100 AND 599),
    content_type TEXT,
    header_names_json TEXT NOT NULL,
    body_size INTEGER CHECK (body_size >= 0),
    body_hash TEXT,
    artifact_hash TEXT,
    body_evidence_id TEXT REFERENCES evidence(evidence_id),
    observation_evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    elapsed_ms INTEGER CHECK (elapsed_ms >= 0),
    http_version TEXT,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX traffic_responses_target_status_idx
    ON traffic_responses(target_id, status_code, observed_at DESC, response_id DESC);

CREATE TABLE traffic_exchanges (
    exchange_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE REFERENCES traffic_requests(request_id),
    endpoint_id TEXT,
    operation_id TEXT,
    structural_fingerprint TEXT NOT NULL,
    source TEXT NOT NULL,
    capture_provider TEXT NOT NULL,
    provider_reference_hash TEXT,
    browser_action_hash TEXT,
    correlation_hash TEXT,
    auth_state TEXT NOT NULL CHECK (auth_state IN ('ANONYMOUS','VERIFIED','UNVERIFIED_IDENTITY')),
    declared_identity_id TEXT REFERENCES registry_identities(identity_id),
    verified_identity_id TEXT REFERENCES registry_identities(identity_id),
    principal_id TEXT,
    principal_state TEXT,
    declared_tenant_ids_json TEXT NOT NULL,
    declared_role_ids_json TEXT NOT NULL,
    browser_session_id TEXT REFERENCES browser_sessions(session_id),
    auth_context_id TEXT REFERENCES auth_contexts(auth_context_id),
    scope_result TEXT NOT NULL CHECK (scope_result IN ('IN_SCOPE','OUT_OF_SCOPE','UNKNOWN')),
    scope_reason TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('REQUEST_ONLY','COMPLETE','FAILED','ABORTED','TIMEOUT')),
    failure_reason TEXT,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('PUBLIC','INTERNAL','SENSITIVE','SECRET')),
    retain INTEGER NOT NULL CHECK (retain IN (0,1)),
    expires_at TEXT,
    pinned INTEGER NOT NULL CHECK (pinned IN (0,1)),
    finding_related INTEGER NOT NULL CHECK (finding_related IN (0,1)),
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK ((auth_state='VERIFIED' AND declared_identity_id=verified_identity_id AND verified_identity_id IS NOT NULL)
        OR (auth_state<>'VERIFIED' AND verified_identity_id IS NULL AND principal_id IS NULL)),
    CHECK (auth_state<>'ANONYMOUS' OR declared_identity_id IS NULL),
    CHECK (pinned=0 OR retain=1)
);
CREATE INDEX traffic_exchanges_target_recent_idx
    ON traffic_exchanges(target_id, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_identity_recent_idx
    ON traffic_exchanges(target_id, verified_identity_id, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_declared_recent_idx
    ON traffic_exchanges(target_id, declared_identity_id, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_session_recent_idx
    ON traffic_exchanges(target_id, browser_session_id, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_auth_recent_idx
    ON traffic_exchanges(target_id, auth_state, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_source_recent_idx
    ON traffic_exchanges(target_id, source, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_endpoint_recent_idx
    ON traffic_exchanges(target_id, endpoint_id, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_operation_recent_idx
    ON traffic_exchanges(target_id, operation_id, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_fingerprint_recent_idx
    ON traffic_exchanges(target_id, structural_fingerprint, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_correlation_recent_idx
    ON traffic_exchanges(target_id, correlation_hash, observed_at DESC, exchange_id DESC);
CREATE INDEX traffic_exchanges_action_recent_idx
    ON traffic_exchanges(target_id, browser_action_hash, observed_at DESC, exchange_id DESC);

CREATE TRIGGER traffic_requests_no_update BEFORE UPDATE ON traffic_requests
BEGIN SELECT RAISE(ABORT, 'immutable traffic request'); END;
CREATE TRIGGER traffic_requests_no_delete BEFORE DELETE ON traffic_requests
BEGIN SELECT RAISE(ABORT, 'immutable traffic request'); END;
CREATE TRIGGER traffic_responses_no_update BEFORE UPDATE ON traffic_responses
BEGIN SELECT RAISE(ABORT, 'immutable traffic response'); END;
CREATE TRIGGER traffic_responses_no_delete BEFORE DELETE ON traffic_responses
BEGIN SELECT RAISE(ABORT, 'immutable traffic response'); END;
