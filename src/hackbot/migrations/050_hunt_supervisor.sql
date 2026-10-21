CREATE TABLE hunt_runs (
    hunt_id TEXT PRIMARY KEY CHECK(hunt_id GLOB 'HUNT-[0-9a-f]*'),
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    package_version INTEGER NOT NULL CHECK(package_version > 0),
    policy_hash TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN
        ('SUPERVISED','RESEARCHER_AUTONOMOUS','PLAN_ONLY','ADVANCED')),
    state TEXT NOT NULL CHECK(state IN
        ('PREPARING','LOGIN_REQUIRED','READY','MAPPING','HUNTING',
         'WAITING_APPROVAL','WAITING_HUMAN','PAUSED_RESOURCE_PRESSURE',
         'COMPLETE','FAILED')),
    reason_code TEXT,
    campaign_id TEXT REFERENCES campaigns(campaign_id),
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE UNIQUE INDEX hunt_one_active_target ON hunt_runs(target_id)
    WHERE state NOT IN ('COMPLETE','FAILED');
CREATE INDEX hunt_target_history ON hunt_runs(target_id,created_at DESC,hunt_id DESC);
CREATE UNIQUE INDEX hunt_campaign_link ON hunt_runs(campaign_id)
    WHERE campaign_id IS NOT NULL;

CREATE TABLE hunt_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id TEXT NOT NULL REFERENCES hunt_runs(hunt_id),
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX hunt_event_history ON hunt_events(hunt_id,event_id DESC);

CREATE TABLE hunt_mapping_sessions (
    hunt_id TEXT NOT NULL REFERENCES hunt_runs(hunt_id),
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    browser_session_id TEXT NOT NULL REFERENCES browser_sessions(session_id),
    pages_attempted INTEGER NOT NULL CHECK(pages_attempted >= 0),
    pages_observed INTEGER NOT NULL CHECK(pages_observed >= 0),
    links_discovered INTEGER NOT NULL CHECK(links_discovered >= 0),
    js_references INTEGER NOT NULL CHECK(js_references >= 0),
    forms_observed INTEGER NOT NULL CHECK(forms_observed >= 0),
    evidence_count INTEGER NOT NULL CHECK(evidence_count >= 0),
    blocked_count INTEGER NOT NULL CHECK(blocked_count >= 0),
    completed_at TEXT NOT NULL,
    PRIMARY KEY(hunt_id,browser_session_id)
);
CREATE INDEX hunt_mapping_target ON hunt_mapping_sessions(target_id,hunt_id);
