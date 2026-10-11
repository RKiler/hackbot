CREATE TABLE plan_runs (
    run_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES skill_plans(plan_id),
    target_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    skill_id TEXT NOT NULL,
    skill_version TEXT NOT NULL,
    skill_hash TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'CREATED','CHECKING_PREREQUISITES','READY','RUNNING','WAITING_APPROVAL',
        'WAITING_HUMAN','BLOCKED','PAUSED','COMPLETED','REJECTED','FAILED',
        'BUDGET_EXHAUSTED','CANCELLED')),
    request_budget INTEGER NOT NULL CHECK (request_budget BETWEEN 0 AND 20),
    requests_consumed INTEGER NOT NULL DEFAULT 0 CHECK (requests_consumed >= 0),
    token_budget INTEGER NOT NULL CHECK (token_budget BETWEEN 0 AND 8192),
    current_step INTEGER NOT NULL DEFAULT 0 CHECK (current_step >= 0),
    approval_id TEXT,
    stop_reason TEXT,
    pause_requested INTEGER NOT NULL DEFAULT 0 CHECK (pause_requested IN (0,1)),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0,1)),
    created_at TEXT NOT NULL,
    started_at TEXT,
    updated_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE UNIQUE INDEX plan_runs_one_open_per_plan ON plan_runs(plan_id) WHERE status IN (
    'CREATED','CHECKING_PREREQUISITES','READY','RUNNING','WAITING_APPROVAL',
    'WAITING_HUMAN','PAUSED');
CREATE INDEX plan_runs_target_recent ON plan_runs(target_id, created_at DESC, run_id DESC);
CREATE INDEX plan_runs_target_status ON plan_runs(target_id, status, updated_at DESC);

CREATE TABLE plan_run_steps (
    step_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    step_type TEXT NOT NULL,
    source_step_index INTEGER,
    action_slot INTEGER,
    role TEXT NOT NULL DEFAULT 'OTHER' CHECK (role IN ('CONTROL','BOUNDARY','OTHER')),
    control_step_id TEXT,
    status TEXT NOT NULL CHECK (status IN (
        'PENDING','READY','WAITING_POLICY','WAITING_APPROVAL','EXECUTING',
        'COMPLETED','FAILED','SKIPPED','BLOCKED','CANCELLED')),
    prerequisite_state TEXT,
    action_id TEXT,
    decision_id TEXT,
    approval_id TEXT,
    permit_id TEXT,
    execution_id TEXT,
    result_id TEXT,
    safe_reason TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(run_id, ordinal)
);
CREATE INDEX plan_run_steps_run_order ON plan_run_steps(run_id, ordinal);
CREATE INDEX plan_run_steps_approval ON plan_run_steps(approval_id);

CREATE TABLE plan_step_results (
    result_id TEXT PRIMARY KEY,
    step_id TEXT NOT NULL UNIQUE REFERENCES plan_run_steps(step_id),
    execution_id TEXT,
    exchange_ids_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    status_code INTEGER,
    response_hash TEXT,
    artifact_hash TEXT,
    duration_ms INTEGER,
    error_class TEXT,
    safe_summary TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER plan_step_results_no_update BEFORE UPDATE ON plan_step_results
BEGIN SELECT RAISE(ABORT, 'plan step results are immutable'); END;
CREATE TRIGGER plan_step_results_no_delete BEFORE DELETE ON plan_step_results
BEGIN SELECT RAISE(ABORT, 'plan step results are immutable'); END;

CREATE TABLE plan_step_manual_links (
    step_id TEXT PRIMARY KEY REFERENCES plan_run_steps(step_id),
    evidence_ids_json TEXT NOT NULL,
    exchange_ids_json TEXT NOT NULL,
    linked_at TEXT NOT NULL
);
CREATE TRIGGER plan_step_manual_links_no_update BEFORE UPDATE ON plan_step_manual_links
BEGIN SELECT RAISE(ABORT, 'plan manual links are immutable'); END;
CREATE TRIGGER plan_step_manual_links_no_delete BEFORE DELETE ON plan_step_manual_links
BEGIN SELECT RAISE(ABORT, 'plan manual links are immutable'); END;

CREATE TABLE plan_run_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    step_id TEXT,
    event_type TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX plan_run_events_run_recent ON plan_run_events(run_id, event_id DESC);
CREATE TRIGGER plan_run_events_no_update BEFORE UPDATE ON plan_run_events
BEGIN SELECT RAISE(ABORT, 'plan events are immutable'); END;
CREATE TRIGGER plan_run_events_no_delete BEFORE DELETE ON plan_run_events
BEGIN SELECT RAISE(ABORT, 'plan events are immutable'); END;
