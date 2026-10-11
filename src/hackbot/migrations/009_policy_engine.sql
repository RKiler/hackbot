CREATE TABLE policy_actions (
    action_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    category TEXT NOT NULL,
    actor TEXT NOT NULL,
    source TEXT NOT NULL,
    method TEXT,
    hypothesis_id TEXT,
    identity_id TEXT,
    session_id TEXT,
    operation TEXT,
    vulnerability_class TEXT,
    object_type TEXT,
    object_ref_hash TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX policy_actions_target_recent_idx
    ON policy_actions(target_id, created_at DESC, action_id DESC);

CREATE TABLE policy_decisions (
    decision_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES policy_actions(action_id),
    target_id TEXT NOT NULL,
    result TEXT NOT NULL CHECK(result IN ('ALLOW','DENY','REQUIRE_APPROVAL')),
    reason_code TEXT NOT NULL,
    scope_result TEXT,
    matched_scope_rule TEXT,
    matched_policy_rule TEXT,
    risk TEXT NOT NULL,
    side_effect TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    approval_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX policy_decisions_action_idx ON policy_decisions(action_id, created_at DESC);
CREATE INDEX policy_decisions_target_idx ON policy_decisions(target_id, created_at DESC);
CREATE TRIGGER policy_decisions_no_update BEFORE UPDATE ON policy_decisions
BEGIN SELECT RAISE(ABORT, 'policy decisions are immutable'); END;
CREATE TRIGGER policy_decisions_no_delete BEFORE DELETE ON policy_decisions
BEGIN SELECT RAISE(ABORT, 'policy decisions are immutable'); END;

CREATE TABLE policy_approvals (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id TEXT NOT NULL UNIQUE,
    decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
    action_id TEXT NOT NULL REFERENCES policy_actions(action_id),
    target_id TEXT NOT NULL,
    hypothesis_id TEXT,
    identity_id TEXT,
    category TEXT NOT NULL,
    risk TEXT NOT NULL,
    operation TEXT,
    object_type TEXT,
    object_ref_hash TEXT,
    action_fingerprint TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('PENDING','APPROVED_ONCE','REJECTED','EXPIRED','CONSUMED')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE INDEX policy_approvals_target_recent_idx
    ON policy_approvals(target_id, sequence DESC);
CREATE INDEX policy_approvals_action_idx
    ON policy_approvals(action_id, policy_version, status);

CREATE TABLE policy_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    decision_id TEXT,
    approval_id TEXT,
    event_type TEXT NOT NULL CHECK(event_type IN
        ('ACTION_PROPOSED','SCOPE_EVALUATED','POLICY_DECIDED',
         'APPROVAL_REQUESTED','APPROVAL_APPROVED_ONCE',
         'APPROVAL_REJECTED','APPROVAL_EXPIRED','APPROVAL_CONSUMED')),
    reason_code TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX policy_events_target_idx
    ON policy_events(target_id, event_id DESC);
CREATE INDEX policy_events_action_idx
    ON policy_events(action_id, event_id DESC);
CREATE TRIGGER policy_events_no_update BEFORE UPDATE ON policy_events
BEGIN SELECT RAISE(ABORT, 'policy history is immutable'); END;
CREATE TRIGGER policy_events_no_delete BEFORE DELETE ON policy_events
BEGIN SELECT RAISE(ABORT, 'policy history is immutable'); END;
