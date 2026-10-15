ALTER TABLE finding_status_events ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE finding_status_events ADD COLUMN actor_alias TEXT;
ALTER TABLE finding_status_events ADD COLUMN workflow_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE finding_submission_metadata (
    finding_id TEXT PRIMARY KEY REFERENCES findings(finding_id),
    platform TEXT,
    program TEXT,
    external_report_id TEXT,
    submitted_at TEXT,
    triage_status TEXT,
    reward_amount TEXT,
    reward_currency TEXT,
    external_duplicate_ref TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE notification_events (
    event_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'CONFIRMED_FINDING','FINDING_READY_FOR_REPORT','MANUAL_REVIEW_REQUIRED',
        'CLEANUP_FAILURE','AUTH_REQUIRES_LOGIN','PLANNER_COMPLETED_WITH_FINDINGS',
        'FINDING_TRIAGE_CHANGED','TEST')),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('FINDING','VALIDATION','PLANNER','OBJECT','TEST')),
    source_id TEXT NOT NULL,
    finding_id TEXT REFERENCES findings(finding_id),
    validation_id TEXT REFERENCES validations(validation_id),
    priority TEXT NOT NULL CHECK (priority IN ('URGENT','HIGH','NORMAL','LOW')),
    workflow_version INTEGER NOT NULL DEFAULT 0,
    dedupe_key TEXT NOT NULL UNIQUE,
    suppressed_count INTEGER NOT NULL DEFAULT 0 CHECK (suppressed_count >= 0),
    created_at TEXT NOT NULL
);
CREATE INDEX notification_events_target_recent ON notification_events(target_id, created_at DESC);
CREATE INDEX notification_events_finding ON notification_events(finding_id, created_at DESC);

CREATE TABLE notification_deliveries (
    delivery_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES notification_events(event_id),
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING','SENDING','RETRY','SENT','FAILED','NEEDS_REVIEW')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 3),
    created_at TEXT NOT NULL,
    claimed_at TEXT,
    sent_at TEXT,
    next_attempt_at TEXT,
    last_error_code TEXT,
    UNIQUE(event_id, provider)
);
CREATE INDEX notification_deliveries_pending ON notification_deliveries(provider, status, next_attempt_at, created_at);

CREATE TABLE notification_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id TEXT NOT NULL REFERENCES notification_deliveries(delivery_id),
    attempt_number INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SENT','RETRY','FAILED','NEEDS_REVIEW')),
    error_code TEXT,
    occurred_at TEXT NOT NULL,
    UNIQUE(delivery_id, attempt_number)
);
CREATE INDEX notification_attempts_recent ON notification_attempts(occurred_at, delivery_id);
CREATE TRIGGER notification_attempts_no_update BEFORE UPDATE ON notification_attempts
BEGIN SELECT RAISE(ABORT, 'notification attempts are immutable'); END;
CREATE TRIGGER notification_attempts_no_delete BEFORE DELETE ON notification_attempts
BEGIN SELECT RAISE(ABORT, 'notification attempts are immutable'); END;

CREATE TABLE report_drafts (
    report_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    version INTEGER NOT NULL CHECK (version > 0),
    validation_id TEXT NOT NULL REFERENCES validations(validation_id),
    source_snapshot_hash TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    content_bytes INTEGER NOT NULL CHECK (content_bytes > 0),
    generator_version TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance IN ('DETERMINISTIC','MODEL_ASSISTED','MANUALLY_EDITED')),
    readiness TEXT NOT NULL CHECK (readiness IN ('READY','NEEDS_MANUAL_REVIEW')),
    severity_status TEXT NOT NULL CHECK (severity_status IN ('UNASSESSED','SUGGESTED','RESEARCHER_CONFIRMED')),
    quality_codes_json TEXT NOT NULL,
    previous_report_id TEXT REFERENCES report_drafts(report_id),
    created_at TEXT NOT NULL,
    UNIQUE(finding_id, version)
);
CREATE INDEX report_drafts_target_recent ON report_drafts(target_id, created_at DESC, report_id DESC);
CREATE INDEX report_drafts_finding_version ON report_drafts(finding_id, version DESC);
CREATE TRIGGER report_drafts_no_update BEFORE UPDATE ON report_drafts
BEGIN SELECT RAISE(ABORT, 'report drafts are immutable'); END;
CREATE TRIGGER report_drafts_no_delete BEFORE DELETE ON report_drafts
BEGIN SELECT RAISE(ABORT, 'report drafts are immutable'); END;

CREATE TABLE report_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    source_snapshot_hash TEXT NOT NULL,
    readiness TEXT NOT NULL CHECK (readiness IN ('READY','NEEDS_EVIDENCE','NEEDS_MANUAL_REVIEW')),
    quality_codes_json TEXT NOT NULL,
    report_id TEXT REFERENCES report_drafts(report_id),
    created_at TEXT NOT NULL
);
CREATE INDEX report_attempts_finding_recent ON report_attempts(finding_id, attempt_id DESC);
CREATE TRIGGER report_attempts_no_update BEFORE UPDATE ON report_attempts
BEGIN SELECT RAISE(ABORT, 'report attempts are immutable'); END;
CREATE TRIGGER report_attempts_no_delete BEFORE DELETE ON report_attempts
BEGIN SELECT RAISE(ABORT, 'report attempts are immutable'); END;
