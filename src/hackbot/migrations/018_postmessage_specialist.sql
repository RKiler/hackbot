CREATE TABLE message_analysis_runs (
    analysis_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    artifact_id TEXT NOT NULL REFERENCES dom_js_artifacts(artifact_id),
    analyzer_version TEXT NOT NULL,
    status TEXT NOT NULL,
    parse_errors INTEGER NOT NULL CHECK (parse_errors >= 0),
    handler_count INTEGER NOT NULL CHECK (handler_count BETWEEN 0 AND 64),
    protocol_count INTEGER NOT NULL CHECK (protocol_count BETWEEN 0 AND 32),
    analyzed_at TEXT NOT NULL,
    UNIQUE(artifact_id,analyzer_version)
);
CREATE INDEX message_analysis_target_time ON message_analysis_runs(target_id,analyzed_at DESC);

CREATE TABLE message_protocol_candidates (
    candidate_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 100),
    status TEXT NOT NULL CHECK (status IN ('STATIC_CANDIDATE','NEEDS_MANUAL_REVIEW',
        'RUNTIME_READY','RUNTIME_TESTED','VALIDATION_READY','REJECTED','STALE')),
    candidate_json TEXT NOT NULL,
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    plan_id TEXT REFERENCES skill_plans(plan_id),
    run_id TEXT REFERENCES plan_runs(run_id),
    validation_id TEXT REFERENCES validations(validation_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX message_candidates_target_priority ON message_protocol_candidates(target_id,priority DESC,candidate_id);

CREATE TABLE message_candidate_assets (
    candidate_id TEXT NOT NULL REFERENCES message_protocol_candidates(candidate_id),
    artifact_id TEXT NOT NULL REFERENCES dom_js_artifacts(artifact_id),
    analysis_id TEXT NOT NULL REFERENCES message_analysis_runs(analysis_id),
    PRIMARY KEY(candidate_id,artifact_id)
);
CREATE INDEX message_candidate_assets_artifact ON message_candidate_assets(artifact_id,candidate_id);

CREATE TABLE message_type_index (
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    type_name TEXT NOT NULL,
    candidate_id TEXT NOT NULL REFERENCES message_protocol_candidates(candidate_id),
    direction TEXT NOT NULL CHECK (direction IN ('RECEIVE','REPLY')),
    PRIMARY KEY(target_id,type_name,candidate_id,direction)
);

CREATE TABLE message_candidate_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL REFERENCES message_protocol_candidates(candidate_id),
    old_status TEXT,
    new_status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
CREATE INDEX message_candidate_events_candidate ON message_candidate_events(candidate_id,event_id);

CREATE TABLE plan_message_dispatches (
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    step_id TEXT NOT NULL REFERENCES plan_run_steps(step_id),
    variant TEXT NOT NULL CHECK (variant IN ('NO_MESSAGE','WRONG_TYPE','TRUSTED',
        'UNRELATED','WRONG_SOURCE','NO_PORT','ATTACKER_PORT','FRESH_REPRODUCTION')),
    accounted_at TEXT NOT NULL,
    PRIMARY KEY(run_id,step_id,variant)
);
