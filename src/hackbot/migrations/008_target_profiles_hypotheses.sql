CREATE TABLE target_profiles (
    profile_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    profile_hash TEXT NOT NULL
);
CREATE INDEX target_profiles_recent_idx
    ON target_profiles(target_id, generated_at DESC, profile_id DESC);

CREATE TABLE profile_source_evidence (
    target_id TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_table TEXT NOT NULL,
    source_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    signal_code TEXT NOT NULL,
    surface_key TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    PRIMARY KEY(target_id, source_kind, source_table, source_id,
                observed_at, signal_code, surface_key)
);

CREATE TABLE hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    category TEXT NOT NULL,
    statement TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'NEW','ENRICHING','READY','NEEDS_RESEARCH','NEEDS_MANUAL_REVIEW',
        'READY_FOR_EXPERIMENT','REJECTED','BLOCKED')),
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100),
    confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
    potential_impact TEXT NOT NULL,
    risk TEXT NOT NULL,
    surface_key TEXT NOT NULL,
    boundary TEXT NOT NULL,
    why_generated TEXT NOT NULL,
    prerequisites_json TEXT NOT NULL,
    missing_json TEXT NOT NULL,
    future_experiment TEXT NOT NULL,
    positive_signal TEXT NOT NULL,
    negative_signal TEXT NOT NULL,
    skill_tags_json TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('DETERMINISTIC','MANUAL')),
    producer TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(target_id, dedupe_key)
);
CREATE INDEX hypotheses_target_priority_idx
    ON hypotheses(target_id, priority DESC, created_at DESC, hypothesis_id DESC);
CREATE INDEX hypotheses_target_status_idx
    ON hypotheses(target_id, status, priority DESC, hypothesis_id DESC);
CREATE TABLE hypothesis_evidence (
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    PRIMARY KEY(hypothesis_id, evidence_id)
);
CREATE TABLE hypothesis_facts (
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    fact_id TEXT NOT NULL REFERENCES facts(fact_id),
    PRIMARY KEY(hypothesis_id, fact_id)
);
CREATE TABLE hypothesis_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    changed_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT,
    old_priority INTEGER,
    new_priority INTEGER,
    reason TEXT NOT NULL
);
CREATE INDEX hypothesis_events_recent_idx
    ON hypothesis_events(hypothesis_id, event_id DESC);
CREATE TRIGGER hypothesis_events_no_update BEFORE UPDATE ON hypothesis_events
BEGIN SELECT RAISE(ABORT, 'hypothesis history is immutable'); END;
CREATE TRIGGER hypothesis_events_no_delete BEFORE DELETE ON hypothesis_events
BEGIN SELECT RAISE(ABORT, 'hypothesis history is immutable'); END;

CREATE TABLE hypothesis_relationships (
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    related_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    relation TEXT NOT NULL CHECK(relation IN
        ('DUPLICATE_OF','DEPENDS_ON','VARIANT_OF','SUPERSEDES')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(hypothesis_id, related_id, relation),
    CHECK(hypothesis_id != related_id)
);

CREATE INDEX facts_target_recent_idx
    ON facts(target_ref, created_at DESC, fact_id DESC);
