CREATE TABLE validations (
    validation_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    plan_id TEXT NOT NULL REFERENCES skill_plans(plan_id),
    hypothesis_id TEXT NOT NULL,
    skill_id TEXT NOT NULL,
    skill_version TEXT NOT NULL,
    skill_hash TEXT NOT NULL,
    validator_id TEXT NOT NULL,
    validator_version TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('DETERMINISTIC','MANUAL')),
    status TEXT NOT NULL CHECK (status IN (
        'CONFIRMED','REJECTED','NEEDS_MANUAL_REVIEW','INSUFFICIENT_EVIDENCE',
        'INVALID_TEST','DUPLICATE_CANDIDATE')),
    confidence_band TEXT NOT NULL CHECK (confidence_band IN ('NONE','LOW','MEDIUM','HIGH')),
    plan_snapshot_hash TEXT NOT NULL,
    evidence_snapshot_hash TEXT NOT NULL,
    supporting_evidence_json TEXT NOT NULL,
    contradicting_evidence_json TEXT NOT NULL,
    controls_json TEXT NOT NULL,
    confirmation_criteria_json TEXT NOT NULL,
    rejection_criteria_json TEXT NOT NULL,
    impact_json TEXT NOT NULL,
    reproduction_count INTEGER NOT NULL CHECK (reproduction_count >= 0),
    limitations_json TEXT NOT NULL,
    reason_codes_json TEXT NOT NULL,
    safe_summary TEXT NOT NULL,
    supersedes_id TEXT REFERENCES validations(validation_id),
    duplicate_of_finding_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX validations_target_recent ON validations(target_id, created_at DESC, validation_id DESC);
CREATE INDEX validations_target_status ON validations(target_id, status, created_at DESC);
CREATE INDEX validations_run_recent ON validations(run_id, created_at DESC);
CREATE INDEX validations_hypothesis_recent ON validations(hypothesis_id, created_at DESC);
CREATE INDEX validations_skill_status ON validations(skill_id, skill_version, status);
CREATE UNIQUE INDEX validations_deterministic_snapshot ON validations(
    run_id, validator_id, validator_version, evidence_snapshot_hash, source)
    WHERE source='DETERMINISTIC';
CREATE TRIGGER validations_no_update BEFORE UPDATE ON validations
BEGIN SELECT RAISE(ABORT, 'validations are immutable'); END;
CREATE TRIGGER validations_no_delete BEFORE DELETE ON validations
BEGIN SELECT RAISE(ABORT, 'validations are immutable'); END;

CREATE TABLE validation_checks (
    validation_id TEXT NOT NULL REFERENCES validations(validation_id),
    criterion_code TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('PASS','FAIL','UNKNOWN')),
    evidence_ids_json TEXT NOT NULL,
    PRIMARY KEY(validation_id, criterion_code)
);
CREATE TRIGGER validation_checks_no_update BEFORE UPDATE ON validation_checks
BEGIN SELECT RAISE(ABORT, 'validation checks are immutable'); END;
CREATE TRIGGER validation_checks_no_delete BEFORE DELETE ON validation_checks
BEGIN SELECT RAISE(ABORT, 'validation checks are immutable'); END;

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    validation_id TEXT NOT NULL UNIQUE REFERENCES validations(validation_id),
    hypothesis_id TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'CONFIRMED','READY_FOR_REPORT','SUBMITTED','TRIAGED','DUPLICATE',
        'INFORMATIVE','RESOLVED','REWARDED')),
    root_cause_fingerprint TEXT NOT NULL UNIQUE,
    surface_fingerprint TEXT NOT NULL,
    object_type TEXT,
    title TEXT NOT NULL,
    safe_summary TEXT NOT NULL,
    demonstrated_impact TEXT NOT NULL,
    potential_impact TEXT,
    preliminary_severity TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX findings_target_recent ON findings(target_id, created_at DESC, finding_id DESC);
CREATE INDEX findings_target_status ON findings(target_id, status, created_at DESC);
CREATE INDEX findings_target_category ON findings(target_id, category, created_at DESC);
CREATE INDEX findings_hypothesis ON findings(hypothesis_id, created_at DESC);

CREATE TABLE finding_evidence (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    PRIMARY KEY(finding_id, evidence_id)
);
CREATE TRIGGER finding_evidence_no_update BEFORE UPDATE ON finding_evidence
BEGIN SELECT RAISE(ABORT, 'finding evidence is immutable'); END;
CREATE TRIGGER finding_evidence_no_delete BEFORE DELETE ON finding_evidence
BEGIN SELECT RAISE(ABORT, 'finding evidence is immutable'); END;

CREATE TABLE finding_locations (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    surface_fingerprint TEXT NOT NULL,
    validation_id TEXT NOT NULL REFERENCES validations(validation_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(finding_id, surface_fingerprint)
);
CREATE TRIGGER finding_locations_no_update BEFORE UPDATE ON finding_locations
BEGIN SELECT RAISE(ABORT, 'finding locations are immutable'); END;
CREATE TRIGGER finding_locations_no_delete BEFORE DELETE ON finding_locations
BEGIN SELECT RAISE(ABORT, 'finding locations are immutable'); END;

CREATE TABLE finding_duplicates (
    validation_id TEXT PRIMARY KEY REFERENCES validations(validation_id),
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    created_at TEXT NOT NULL
);
CREATE INDEX finding_duplicates_finding ON finding_duplicates(finding_id, created_at DESC);

CREATE TABLE finding_status_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX finding_status_events_finding ON finding_status_events(finding_id, event_id DESC);
CREATE TRIGGER finding_status_events_no_update BEFORE UPDATE ON finding_status_events
BEGIN SELECT RAISE(ABORT, 'finding status events are immutable'); END;
CREATE TRIGGER finding_status_events_no_delete BEFORE DELETE ON finding_status_events
BEGIN SELECT RAISE(ABORT, 'finding status events are immutable'); END;
