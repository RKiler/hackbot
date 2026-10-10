CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    evidence_type TEXT NOT NULL,
    target_ref TEXT,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    content_kind TEXT NOT NULL CHECK (content_kind IN ('INLINE', 'ARTIFACT')),
    content_size INTEGER NOT NULL CHECK (content_size >= 0),
    inline_content BLOB,
    artifact_hash TEXT,
    metadata_json TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('PUBLIC', 'INTERNAL', 'SENSITIVE', 'SECRET')),
    redaction_status TEXT NOT NULL CHECK (redaction_status IN ('ORIGINAL', 'REDACTED', 'WITHHELD')),
    provenance_json TEXT NOT NULL,
    replaces_evidence_id TEXT REFERENCES evidence(evidence_id),
    CHECK (
        (content_kind = 'INLINE' AND inline_content IS NOT NULL AND artifact_hash IS NULL)
        OR (content_kind = 'ARTIFACT' AND inline_content IS NULL AND artifact_hash = content_hash)
    )
);

CREATE INDEX evidence_created_idx ON evidence(created_at DESC, evidence_id DESC);
CREATE INDEX evidence_target_created_idx ON evidence(target_ref, created_at DESC, evidence_id DESC);

CREATE TABLE evidence_policy_events (
    event_id INTEGER PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    retain INTEGER NOT NULL CHECK (retain IN (0, 1)),
    expires_at TEXT,
    pinned INTEGER NOT NULL CHECK (pinned IN (0, 1)),
    finding_related INTEGER NOT NULL CHECK (finding_related IN (0, 1)),
    changed_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    CHECK (pinned = 0 OR retain = 1)
);

CREATE INDEX evidence_policy_latest_idx ON evidence_policy_events(evidence_id, event_id DESC);

CREATE TABLE facts (
    fact_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object_ref TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    target_ref TEXT,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('PUBLIC', 'INTERNAL', 'SENSITIVE', 'SECRET'))
);

CREATE INDEX facts_subject_created_idx ON facts(subject, created_at DESC, fact_id DESC);
CREATE INDEX facts_subject_predicate_created_idx ON facts(subject, predicate, created_at DESC, fact_id DESC);
CREATE INDEX facts_object_created_idx ON facts(object_ref, created_at DESC, fact_id DESC);
CREATE INDEX facts_object_predicate_created_idx ON facts(object_ref, predicate, created_at DESC, fact_id DESC);

CREATE TABLE fact_evidence (
    fact_id TEXT NOT NULL REFERENCES facts(fact_id),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    PRIMARY KEY (fact_id, evidence_id)
);

CREATE INDEX fact_evidence_evidence_idx ON fact_evidence(evidence_id);

CREATE TABLE fact_status_events (
    event_id INTEGER PRIMARY KEY,
    fact_id TEXT NOT NULL REFERENCES facts(fact_id),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'DISPUTED', 'RETRACTED')),
    changed_at TEXT NOT NULL,
    producer TEXT NOT NULL,
    reason TEXT NOT NULL,
    supporting_evidence_id TEXT REFERENCES evidence(evidence_id),
    related_fact_id TEXT REFERENCES facts(fact_id)
);

CREATE INDEX fact_status_latest_idx ON fact_status_events(fact_id, event_id DESC);

CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'immutable evidence'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'immutable evidence'); END;
CREATE TRIGGER facts_no_update BEFORE UPDATE ON facts
BEGIN SELECT RAISE(ABORT, 'immutable fact'); END;
CREATE TRIGGER facts_no_delete BEFORE DELETE ON facts
BEGIN SELECT RAISE(ABORT, 'immutable fact'); END;
CREATE TRIGGER fact_evidence_no_update BEFORE UPDATE ON fact_evidence
BEGIN SELECT RAISE(ABORT, 'immutable fact evidence'); END;
CREATE TRIGGER fact_evidence_no_delete BEFORE DELETE ON fact_evidence
BEGIN SELECT RAISE(ABORT, 'immutable fact evidence'); END;
CREATE TRIGGER evidence_policy_no_update BEFORE UPDATE ON evidence_policy_events
BEGIN SELECT RAISE(ABORT, 'immutable retention history'); END;
CREATE TRIGGER evidence_policy_no_delete BEFORE DELETE ON evidence_policy_events
BEGIN SELECT RAISE(ABORT, 'immutable retention history'); END;
CREATE TRIGGER fact_status_no_update BEFORE UPDATE ON fact_status_events
BEGIN SELECT RAISE(ABORT, 'immutable fact status history'); END;
CREATE TRIGGER fact_status_no_delete BEFORE DELETE ON fact_status_events
BEGIN SELECT RAISE(ABORT, 'immutable fact status history'); END;
