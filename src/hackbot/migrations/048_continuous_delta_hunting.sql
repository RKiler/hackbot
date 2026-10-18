CREATE TABLE continuous_targets (
    target_id TEXT PRIMARY KEY REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
    cadence_seconds INTEGER NOT NULL CHECK(cadence_seconds IN (3600,21600,86400)),
    minimum_relevance INTEGER NOT NULL CHECK(minimum_relevance BETWEEN 0 AND 100),
    cooldown_seconds INTEGER NOT NULL CHECK(cooldown_seconds BETWEEN 3600 AND 604800),
    daily_campaign_cap INTEGER NOT NULL CHECK(daily_campaign_cap BETWEEN 0 AND 24),
    request_cap INTEGER NOT NULL CHECK(request_cap BETWEEN 0 AND 40),
    status TEXT NOT NULL CHECK(status IN
        ('PENDING','RUNNING','IDLE','DEGRADED','PAUSED','DISABLED','FAILED')),
    next_check_at TEXT,
    last_checked_at TEXT,
    last_success_at TEXT,
    last_snapshot_id INTEGER,
    last_event_at TEXT,
    last_event_id INTEGER,
    backfill_cursor TEXT,
    backfill_window_start TEXT,
    backfill_window_end TEXT,
    backfill_highwater_at TEXT,
    backfill_highwater_id INTEGER,
    last_bootstrap_at TEXT,
    last_bootstrap_id TEXT,
    last_js_at TEXT,
    last_delta_at TEXT,
    last_campaign_at TEXT,
    backlog_min_count INTEGER NOT NULL DEFAULT 0 CHECK(backlog_min_count >= 0),
    backlog_oldest_at TEXT,
    error_code TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX continuous_targets_due ON continuous_targets(enabled,next_check_at,target_id);

CREATE TABLE continuous_target_specialists (
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    specialist TEXT NOT NULL CHECK(specialist IN
        ('AUTHORIZATION','API_GRAPHQL','DOM_XSS','POSTMESSAGE','EXPOSURE')),
    PRIMARY KEY(target_id,specialist)
);

CREATE TABLE continuous_target_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    event_type TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
CREATE INDEX continuous_target_events_target ON continuous_target_events(target_id,event_id DESC);

CREATE TABLE delta_watch_runs (
    watch_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    trigger_kind TEXT NOT NULL CHECK(trigger_kind IN ('SCHEDULED','MANUAL','FIXTURE')),
    status TEXT NOT NULL CHECK(status IN ('RUNNING','IDLE','DEGRADED','PAUSED','FAILED')),
    baseline INTEGER NOT NULL DEFAULT 0 CHECK(baseline IN (0,1)),
    source_kind TEXT NOT NULL CHECK(source_kind IN ('RECON','COLD_START','NONE')),
    snapshot_id INTEGER,
    window_start TEXT,
    window_end TEXT,
    events_scanned INTEGER NOT NULL DEFAULT 0 CHECK(events_scanned >= 0),
    candidates_created INTEGER NOT NULL DEFAULT 0 CHECK(candidates_created >= 0),
    ignored_count INTEGER NOT NULL DEFAULT 0 CHECK(ignored_count >= 0),
    campaigns_started INTEGER NOT NULL DEFAULT 0 CHECK(campaigns_started >= 0),
    backlog_min_count INTEGER NOT NULL DEFAULT 0 CHECK(backlog_min_count >= 0),
    error_code TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX delta_watch_runs_target ON delta_watch_runs(target_id,started_at DESC,watch_id DESC);
CREATE UNIQUE INDEX delta_watch_runs_active_target ON delta_watch_runs(target_id)
    WHERE status='RUNNING';

CREATE TABLE delta_observations (
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    source_kind TEXT NOT NULL CHECK(source_kind IN ('RECON','COLD_START')),
    entity_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    semantic_hash TEXT,
    artifact_id TEXT REFERENCES dom_js_artifacts(artifact_id),
    observed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(target_id,source_kind,entity_key)
);

CREATE TABLE delta_candidates (
    delta_id TEXT PRIMARY KEY CHECK(delta_id GLOB 'DELTA-[0-9a-f]*'),
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    delta_type TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK(source_kind IN ('RECON','COLD_START')),
    source_ref TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    location_hash TEXT NOT NULL,
    display_location TEXT NOT NULL,
    old_fingerprint TEXT,
    new_fingerprint TEXT NOT NULL,
    semantic_hash TEXT,
    observed_at TEXT NOT NULL,
    relevance INTEGER NOT NULL CHECK(relevance BETWEEN 0 AND 100),
    status TEXT NOT NULL CHECK(status IN
        ('NEW','CLASSIFIED','IGNORED','DEFERRED','CAMPAIGN_READY',
         'CAMPAIGN_STARTED','RESOLVED','SUPERSEDED','BLOCKED')),
    dedupe_key TEXT NOT NULL,
    evidence_id TEXT REFERENCES evidence(evidence_id),
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    campaign_id TEXT REFERENCES campaigns(campaign_id),
    reason_code TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(target_id,dedupe_key)
);
CREATE INDEX delta_candidates_target_time ON delta_candidates(target_id,observed_at DESC,delta_id DESC);
CREATE INDEX delta_candidates_ready ON delta_candidates(target_id,status,relevance DESC,observed_at DESC);
CREATE INDEX delta_candidates_campaign ON delta_candidates(campaign_id);
CREATE INDEX delta_candidates_evidence ON delta_candidates(evidence_id);

CREATE TRIGGER retired_link_delta_candidate_insert BEFORE INSERT ON delta_candidates
WHEN NEW.evidence_id IS NOT NULL AND EXISTS
    (SELECT 1 FROM evidence_payload_retirements WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_delta_candidate_update
BEFORE UPDATE OF evidence_id ON delta_candidates
WHEN NEW.evidence_id IS NOT NULL AND EXISTS
    (SELECT 1 FROM evidence_payload_retirements WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER delta_candidate_evidence_no_retirement
BEFORE INSERT ON evidence_payload_retirements
WHEN EXISTS (SELECT 1 FROM delta_candidates WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'delta Evidence cannot be retired'); END;

CREATE TABLE delta_candidate_hints (
    delta_id TEXT NOT NULL REFERENCES delta_candidates(delta_id),
    specialist TEXT NOT NULL CHECK(specialist IN
        ('AUTHORIZATION','API_GRAPHQL','DOM_XSS','POSTMESSAGE','EXPOSURE')),
    PRIMARY KEY(delta_id,specialist)
);

CREATE TABLE delta_candidate_tags (
    delta_id TEXT NOT NULL REFERENCES delta_candidates(delta_id),
    tag TEXT NOT NULL,
    PRIMARY KEY(delta_id,tag)
);

CREATE TABLE delta_candidate_hypotheses (
    delta_id TEXT NOT NULL REFERENCES delta_candidates(delta_id),
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    PRIMARY KEY(delta_id,hypothesis_id)
);
CREATE INDEX delta_candidate_hypotheses_hypothesis
    ON delta_candidate_hypotheses(hypothesis_id,delta_id);

CREATE TABLE delta_candidate_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    delta_id TEXT NOT NULL REFERENCES delta_candidates(delta_id),
    old_status TEXT,
    new_status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
CREATE INDEX delta_candidate_events_delta ON delta_candidate_events(delta_id,event_id DESC);

CREATE TABLE delta_cooldowns (
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    root_key TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    next_allowed_at TEXT NOT NULL,
    last_campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(target_id,root_key,state_hash)
);

CREATE TABLE delta_campaign_focus (
    campaign_id TEXT PRIMARY KEY REFERENCES campaigns(campaign_id),
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    location_hash TEXT NOT NULL,
    recon_asset_id INTEGER,
    automatic INTEGER NOT NULL CHECK(automatic IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE delta_campaign_focus_deltas (
    campaign_id TEXT NOT NULL REFERENCES delta_campaign_focus(campaign_id),
    delta_id TEXT NOT NULL UNIQUE REFERENCES delta_candidates(delta_id),
    PRIMARY KEY(campaign_id,delta_id)
);

CREATE TABLE delta_campaign_focus_hypotheses (
    campaign_id TEXT NOT NULL REFERENCES delta_campaign_focus(campaign_id),
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    PRIMARY KEY(campaign_id,hypothesis_id)
);

CREATE TABLE delta_campaign_focus_specialists (
    campaign_id TEXT NOT NULL REFERENCES delta_campaign_focus(campaign_id),
    specialist TEXT NOT NULL CHECK(specialist IN
        ('AUTHORIZATION','API_GRAPHQL','DOM_XSS','POSTMESSAGE','EXPOSURE')),
    PRIMARY KEY(campaign_id,specialist)
);

CREATE TABLE delta_asset_refresh (
    campaign_id TEXT PRIMARY KEY REFERENCES delta_campaign_focus(campaign_id),
    target_id TEXT NOT NULL REFERENCES continuous_targets(target_id),
    recon_asset_id INTEGER NOT NULL,
    expected_sha256 TEXT,
    status TEXT NOT NULL CHECK(status IN
        ('PENDING','INTENT','COMPLETED','AMBIGUOUS','BLOCKED')),
    requests_reserved INTEGER NOT NULL DEFAULT 0 CHECK(requests_reserved BETWEEN 0 AND 3),
    artifact_id TEXT REFERENCES dom_js_artifacts(artifact_id),
    reason_code TEXT,
    updated_at TEXT NOT NULL
);
