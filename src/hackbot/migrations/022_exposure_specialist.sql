CREATE TABLE exposure_candidates (
    candidate_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    category TEXT NOT NULL,
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100),
    status TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    plan_id TEXT REFERENCES skill_plans(plan_id),
    run_id TEXT REFERENCES plan_runs(run_id),
    validation_id TEXT REFERENCES validations(validation_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX exposure_candidates_target_rank
    ON exposure_candidates(target_id, priority DESC, candidate_id);

CREATE TABLE exposure_candidate_sources (
    candidate_id TEXT NOT NULL REFERENCES exposure_candidates(candidate_id),
    source_kind TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    artifact_sha256 TEXT,
    evidence_id TEXT NOT NULL,
    current INTEGER NOT NULL DEFAULT 1 CHECK(current IN (0,1)),
    observed_at TEXT NOT NULL,
    PRIMARY KEY(candidate_id, source_kind, source_ref, evidence_id)
);
CREATE INDEX exposure_sources_ref
    ON exposure_candidate_sources(source_kind, source_ref, candidate_id);

CREATE TABLE exposure_candidate_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL REFERENCES exposure_candidates(candidate_id),
    old_status TEXT,
    new_status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
