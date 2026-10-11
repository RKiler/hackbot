CREATE TABLE executor_permits (
    permit_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
    action_id TEXT NOT NULL REFERENCES policy_actions(action_id),
    target_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    category TEXT NOT NULL,
    identity_id TEXT,
    action_fingerprint TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    scope_rule TEXT,
    approval_id TEXT,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE INDEX executor_permits_action_idx ON executor_permits(action_id, expires_at);

CREATE TABLE executor_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id TEXT,
    action_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    exchange_id TEXT,
    occurred_at TEXT NOT NULL
);
CREATE INDEX executor_events_target_idx ON executor_events(target_id, event_id DESC);
CREATE TRIGGER executor_events_no_update BEFORE UPDATE ON executor_events
BEGIN SELECT RAISE(ABORT, 'executor events are immutable'); END;
CREATE TRIGGER executor_events_no_delete BEFORE DELETE ON executor_events
BEGIN SELECT RAISE(ABORT, 'executor events are immutable'); END;
