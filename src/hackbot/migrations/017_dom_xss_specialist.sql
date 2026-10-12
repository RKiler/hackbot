CREATE TABLE dom_js_artifacts (
    artifact_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    recon_asset_id INTEGER,
    asset_url_sha256 TEXT NOT NULL,
    recon_sha256 TEXT,
    artifact_sha256 TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    retrieval_exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    state TEXT NOT NULL CHECK (state IN ('CURRENT','UNVERIFIED_CURRENT','RECON_HASH_DRIFT','STALE')),
    source TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    UNIQUE(target_id,asset_url_sha256,artifact_sha256)
);
CREATE INDEX dom_js_artifacts_target_url ON dom_js_artifacts(target_id,asset_url_sha256,retrieved_at DESC);

CREATE TABLE dom_source_maps (
    map_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    js_artifact_id TEXT NOT NULL REFERENCES dom_js_artifacts(artifact_id),
    map_url_sha256 TEXT NOT NULL,
    map_sha256 TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    retrieval_exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    retrieved_at TEXT NOT NULL,
    UNIQUE(js_artifact_id,map_url_sha256,map_sha256)
);
CREATE INDEX dom_source_maps_js ON dom_source_maps(js_artifact_id,retrieved_at DESC);

CREATE TABLE dom_analysis_runs (
    analysis_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    artifact_id TEXT NOT NULL REFERENCES dom_js_artifacts(artifact_id),
    analyzer_version TEXT NOT NULL,
    status TEXT NOT NULL,
    parse_errors INTEGER NOT NULL CHECK (parse_errors >= 0),
    candidate_count INTEGER NOT NULL CHECK (candidate_count BETWEEN 0 AND 16),
    analyzed_at TEXT NOT NULL,
    UNIQUE(artifact_id,analyzer_version)
);
CREATE INDEX dom_analysis_runs_target_time ON dom_analysis_runs(target_id,analyzed_at DESC,analysis_id);

CREATE TABLE dom_flow_candidates (
    candidate_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    artifact_id TEXT NOT NULL REFERENCES dom_js_artifacts(artifact_id),
    analysis_id TEXT NOT NULL REFERENCES dom_analysis_runs(analysis_id),
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    status TEXT NOT NULL CHECK (status IN ('DISCOVERED','TRACING','STATICALLY_SUPPORTED',
        'RUNTIME_READY','RUNTIME_TESTED','REJECTED','NEEDS_MANUAL_REVIEW',
        'VALIDATION_READY','ANALYSIS_LIMIT_REACHED','PARSE_FAILED','STALE')),
    candidate_json TEXT NOT NULL,
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    plan_id TEXT REFERENCES skill_plans(plan_id),
    run_id TEXT REFERENCES plan_runs(run_id),
    validation_id TEXT REFERENCES validations(validation_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX dom_flow_candidates_target_score ON dom_flow_candidates(target_id,score DESC,candidate_id);
CREATE INDEX dom_flow_candidates_artifact ON dom_flow_candidates(artifact_id,status);

CREATE TABLE dom_candidate_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL REFERENCES dom_flow_candidates(candidate_id),
    old_status TEXT,
    new_status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
CREATE INDEX dom_candidate_events_candidate ON dom_candidate_events(candidate_id,event_id);

CREATE TABLE plan_dom_dispatches (
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    step_id TEXT NOT NULL REFERENCES plan_run_steps(step_id),
    variant TEXT NOT NULL CHECK (variant IN ('INERT','BENIGN','DIRECT_DANGEROUS',
        'ENCODED_ONCE','ENCODED_TWICE','FRESH_REPRODUCTION')),
    accounted_at TEXT NOT NULL,
    PRIMARY KEY(run_id,step_id,variant)
);
CREATE INDEX plan_dom_dispatches_step ON plan_dom_dispatches(step_id,accounted_at);
