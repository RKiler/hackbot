CREATE TABLE planner_runs (
    run_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    package_version INTEGER NOT NULL,
    policy_hash TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('ANALYZE_ONLY','PLAN_ONLY','BOUNDED_AUTONOMOUS')),
    status TEXT NOT NULL CHECK(status IN (
        'CREATED','LOADING_CONTEXT','RANKING','RESOLVING_GAPS','READY','RUNNING',
        'WAITING_RESEARCH','WAITING_LOGIN','WAITING_APPROVAL','WAITING_HUMAN',
        'PAUSED','COMPLETED','BLOCKED','FAILED','CANCELLED','BUDGET_EXHAUSTED')),
    limits_json TEXT NOT NULL,
    usage_json TEXT NOT NULL,
    readiness_json TEXT NOT NULL DEFAULT '{}',
    context_hash TEXT,
    candidate_count INTEGER NOT NULL DEFAULT 0,
    selected_count INTEGER NOT NULL DEFAULT 0,
    plans_created INTEGER NOT NULL DEFAULT 0,
    plans_executed INTEGER NOT NULL DEFAULT 0,
    validations INTEGER NOT NULL DEFAULT 0,
    findings INTEGER NOT NULL DEFAULT 0,
    manual_reviews INTEGER NOT NULL DEFAULT 0,
    research_requests INTEGER NOT NULL DEFAULT 0,
    stop_reason TEXT,
    planner_version TEXT NOT NULL,
    started_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX planner_runs_target_recent ON planner_runs(target_id,created_at DESC,run_id DESC);
CREATE INDEX planner_runs_restartable ON planner_runs(status,run_id);
CREATE UNIQUE INDEX planner_one_active_target ON planner_runs(target_id)
    WHERE status IN ('CREATED','LOADING_CONTEXT','RANKING','RESOLVING_GAPS','READY',
                     'RUNNING','WAITING_RESEARCH','WAITING_LOGIN','WAITING_APPROVAL',
                     'WAITING_HUMAN','PAUSED');

CREATE TABLE planner_candidates (
    candidate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES planner_runs(run_id),
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    source_kind TEXT NOT NULL CHECK(source_kind IN
        ('HYPOTHESIS','AUTHORIZATION','API_GRAPHQL','DOM_XSS','POSTMESSAGE','EXPOSURE')),
    source_id TEXT NOT NULL,
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    specialist TEXT NOT NULL CHECK(specialist IN
        ('AUTHORIZATION','API_GRAPHQL','DOM_XSS','POSTMESSAGE','EXPOSURE')),
    category TEXT NOT NULL,
    root_cause_key TEXT NOT NULL,
    surface_hash TEXT NOT NULL,
    score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
    expected_value INTEGER NOT NULL CHECK(expected_value BETWEEN 0 AND 100),
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100),
    estimated_requests INTEGER NOT NULL CHECK(estimated_requests BETWEEN 0 AND 20),
    estimated_browser INTEGER NOT NULL CHECK(estimated_browser BETWEEN 0 AND 20),
    estimated_tokens INTEGER NOT NULL CHECK(estimated_tokens BETWEEN 0 AND 4000),
    risk TEXT NOT NULL CHECK(risk IN ('LOW','MEDIUM','HIGH')),
    evidence_strength INTEGER NOT NULL CHECK(evidence_strength BETWEEN 0 AND 100),
    freshness TEXT NOT NULL CHECK(freshness IN ('CURRENT','STALE','UNKNOWN')),
    gaps_json TEXT NOT NULL,
    reason_codes_json TEXT NOT NULL,
    source_refs_json TEXT NOT NULL,
    skill_ids_json TEXT NOT NULL,
    handoffs_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('SELECTED','DEFERRED','BLOCKED','DUPLICATE','NEEDS_REFRESH','PLANNED',
         'RUNNING','WAITING','VALIDATED','REJECTED','SKIPPED')),
    related_candidate_id TEXT REFERENCES planner_candidates(candidate_id),
    plan_id TEXT REFERENCES skill_plans(plan_id),
    plan_run_id TEXT REFERENCES plan_runs(run_id),
    validation_id TEXT REFERENCES validations(validation_id),
    finding_id TEXT REFERENCES findings(finding_id),
    override TEXT NOT NULL DEFAULT 'NONE' CHECK(override IN
        ('NONE','PIN','DEPRIORITIZE','EXCLUDE')),
    override_specialist TEXT,
    override_skill_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    state_hash TEXT NOT NULL DEFAULT '',
    UNIQUE(run_id,source_kind,source_id)
);
CREATE INDEX planner_candidates_run_rank ON planner_candidates(run_id,priority DESC,candidate_id);
CREATE INDEX planner_candidates_root ON planner_candidates(target_id,root_cause_key,run_id);
CREATE INDEX planner_candidates_source ON planner_candidates(target_id,source_kind,source_id);

CREATE TABLE planner_candidate_relationships (
    candidate_id TEXT NOT NULL REFERENCES planner_candidates(candidate_id),
    related_id TEXT NOT NULL REFERENCES planner_candidates(candidate_id),
    relation TEXT NOT NULL CHECK(relation IN (
        'DUPLICATE_OF','VARIANT_OF','DEPENDS_ON','BLOCKED_BY','ENRICHES',
        'SHARES_ROOT_CAUSE','SUPERSEDED_BY')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(candidate_id,related_id,relation),
    CHECK(candidate_id != related_id)
);
CREATE INDEX planner_candidate_rel_related ON planner_candidate_relationships(related_id,relation);

CREATE TABLE planner_tasks (
    task_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES planner_runs(run_id),
    candidate_id TEXT NOT NULL REFERENCES planner_candidates(candidate_id),
    task_type TEXT NOT NULL CHECK(task_type IN
        ('RESOLVE_IDENTITY','RESOLVE_OBJECT','REFRESH_TRAFFIC','REFRESH_ASSET',
         'REQUEST_RESEARCH','CREATE_DISPOSABLE_OBJECT','CREATE_PLAN','RUN_PLAN',
         'VALIDATE_RUN','MANUAL_REVIEW')),
    status TEXT NOT NULL CHECK(status IN
        ('PENDING','READY','RUNNING','WAITING','COMPLETED','FAILED','BLOCKED','SKIPPED','CANCELLED')),
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100),
    budget_json TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 2),
    result_ref TEXT,
    reason_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(candidate_id,task_type)
);
CREATE INDEX planner_tasks_run_status ON planner_tasks(run_id,status,priority DESC,task_id);
CREATE TABLE planner_budget_reservations (
    task_id TEXT PRIMARY KEY REFERENCES planner_tasks(task_id),
    run_id TEXT NOT NULL REFERENCES planner_runs(run_id),
    requests INTEGER NOT NULL CHECK(requests BETWEEN 0 AND 20),
    browser_actions INTEGER NOT NULL CHECK(browser_actions BETWEEN 0 AND 20),
    tokens INTEGER NOT NULL CHECK(tokens BETWEEN 0 AND 4000),
    reserved_at TEXT NOT NULL
);
CREATE TABLE planner_task_dependencies (
    task_id TEXT NOT NULL REFERENCES planner_tasks(task_id),
    depends_on TEXT NOT NULL REFERENCES planner_tasks(task_id),
    PRIMARY KEY(task_id,depends_on),
    CHECK(task_id != depends_on)
);

CREATE TABLE planner_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES planner_runs(run_id),
    candidate_id TEXT REFERENCES planner_candidates(candidate_id),
    task_id TEXT REFERENCES planner_tasks(task_id),
    event_type TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    safe_refs_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX planner_events_run_recent ON planner_events(run_id,event_id DESC);
CREATE TRIGGER planner_events_no_update BEFORE UPDATE ON planner_events
BEGIN SELECT RAISE(ABORT, 'planner history is immutable'); END;
CREATE TRIGGER planner_events_no_delete BEFORE DELETE ON planner_events
BEGIN SELECT RAISE(ABORT, 'planner history is immutable'); END;

CREATE TABLE planner_branch_memory (
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    root_cause_key TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN
        ('CONFIRMED','DUPLICATE','REJECTED','FAILED','MANUAL_REVIEW','BLOCKED')),
    source_run_id TEXT NOT NULL REFERENCES planner_runs(run_id),
    reason_code TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(target_id,root_cause_key,state_hash,outcome)
);
CREATE INDEX planner_branch_memory_target ON planner_branch_memory(target_id,root_cause_key);
