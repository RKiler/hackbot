CREATE TABLE campaigns (
    campaign_id TEXT PRIMARY KEY CHECK(campaign_id GLOB 'CMP-[0-9a-f]*'),
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    package_version INTEGER NOT NULL CHECK(package_version > 0),
    policy_hash TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('ANALYZE_ONLY','PLAN_ONLY','BOUNDED_AUTONOMOUS')),
    status TEXT NOT NULL CHECK(status IN
        ('CREATED','ASSESSING_READINESS','RUNNING','WAITING_LOGIN','WAITING_APPROVAL',
         'WAITING_RESEARCH','WAITING_HUMAN','PAUSED','COMPLETED','BLOCKED','FAILED',
         'CANCELLED','BUDGET_EXHAUSTED','TIME_EXHAUSTED','CLEANUP_REQUIRED')),
    requested_by TEXT NOT NULL,
    max_cycles INTEGER NOT NULL CHECK(max_cycles BETWEEN 1 AND 8),
    seconds_limit INTEGER NOT NULL CHECK(seconds_limit BETWEEN 30 AND 14400),
    requests_limit INTEGER NOT NULL CHECK(requests_limit BETWEEN 0 AND 400),
    browser_limit INTEGER NOT NULL CHECK(browser_limit BETWEEN 0 AND 160),
    research_limit INTEGER NOT NULL CHECK(research_limit BETWEEN 0 AND 8),
    tokens_limit INTEGER NOT NULL CHECK(tokens_limit BETWEEN 0 AND 80000),
    setup_limit INTEGER NOT NULL CHECK(setup_limit BETWEEN 0 AND 8),
    cleanup_reserve INTEGER NOT NULL CHECK(cleanup_reserve BETWEEN 0 AND 32),
    current_cycle INTEGER NOT NULL DEFAULT 0 CHECK(current_cycle BETWEEN 0 AND 8),
    requests_used INTEGER NOT NULL DEFAULT 0 CHECK(requests_used >= 0),
    browser_used INTEGER NOT NULL DEFAULT 0 CHECK(browser_used >= 0),
    research_used INTEGER NOT NULL DEFAULT 0 CHECK(research_used >= 0),
    tokens_used INTEGER NOT NULL DEFAULT 0 CHECK(tokens_used >= 0),
    setup_used INTEGER NOT NULL DEFAULT 0 CHECK(setup_used >= 0),
    cleanup_used INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_used >= 0),
    stop_reason TEXT,
    readiness_code TEXT,
    coverage_digest TEXT,
    campaign_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    updated_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE UNIQUE INDEX campaign_one_active_target ON campaigns(target_id)
    WHERE status NOT IN ('COMPLETED','BLOCKED','FAILED','CANCELLED',
                         'BUDGET_EXHAUSTED','TIME_EXHAUSTED','CLEANUP_REQUIRED');
CREATE INDEX campaign_target_history ON campaigns(target_id,created_at DESC,campaign_id DESC);

CREATE TABLE campaign_cycles (
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    cycle_number INTEGER NOT NULL CHECK(cycle_number BETWEEN 1 AND 8),
    status TEXT NOT NULL CHECK(status IN ('ASSESSING','PREREQUISITE','PLANNING',
                                         'RUNNING','WAITING','COMPLETED','AMBIGUOUS')),
    package_version INTEGER NOT NULL CHECK(package_version > 0),
    policy_hash TEXT NOT NULL,
    behaviour_run_id TEXT REFERENCES behaviour_runs(run_id),
    planner_run_id TEXT UNIQUE REFERENCES planner_runs(run_id),
    source_digest TEXT,
    readiness_digest TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(campaign_id,cycle_number)
);

CREATE TABLE campaign_work (
    work_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    cycle_number INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('BOOTSTRAP','BEHAVIOUR','RESEARCH','PLANNER','CLEANUP')),
    status TEXT NOT NULL CHECK(status IN ('INTENT','LINKED','COMPLETED','AMBIGUOUS','CANCELLED')),
    child_id TEXT CHECK(child_id IS NULL OR
        (kind='BOOTSTRAP' AND child_id GLOB 'BOOT-[0-9a-f]*') OR
        (kind='BEHAVIOUR' AND child_id GLOB 'LEARN-[0-9a-f]*') OR
        (kind='RESEARCH' AND child_id GLOB 'RREQ-[0-9a-f]*') OR
        (kind='PLANNER' AND child_id GLOB 'PLRUN-[0-9a-f]*') OR
        (kind='CLEANUP' AND child_id GLOB 'TESTOBJ-[0-9a-f]*')),
    requests_allocated INTEGER NOT NULL CHECK(requests_allocated >= 0),
    browser_allocated INTEGER NOT NULL CHECK(browser_allocated >= 0),
    research_allocated INTEGER NOT NULL CHECK(research_allocated >= 0),
    tokens_allocated INTEGER NOT NULL CHECK(tokens_allocated >= 0),
    setup_allocated INTEGER NOT NULL CHECK(setup_allocated >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(campaign_id,cycle_number) REFERENCES campaign_cycles(campaign_id,cycle_number),
    UNIQUE(campaign_id,kind,child_id)
);
CREATE INDEX campaign_work_cycle ON campaign_work(campaign_id,cycle_number,kind,status);
CREATE UNIQUE INDEX campaign_work_child_once ON campaign_work(kind,child_id)
    WHERE child_id IS NOT NULL;

CREATE TABLE campaign_task_claims (
    work_id TEXT NOT NULL REFERENCES campaign_work(work_id),
    planner_task_id TEXT NOT NULL REFERENCES planner_tasks(task_id),
    kind TEXT NOT NULL CHECK(kind IN ('SETUP','RESEARCH')),
    claimed_at TEXT NOT NULL,
    PRIMARY KEY(work_id,planner_task_id,kind)
);
CREATE INDEX campaign_task_claims_kind ON campaign_task_claims(work_id,kind);

CREATE TABLE campaign_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    cycle_number INTEGER CHECK(cycle_number BETWEEN 0 AND 8),
    work_id TEXT REFERENCES campaign_work(work_id),
    event_type TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX campaign_event_history ON campaign_events(campaign_id,event_id DESC);

CREATE TABLE campaign_suppressions (
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    root_key TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('CONFIRMED','REJECTED','MANUAL_EXCLUDE',
                                     'DEPRIORITIZED','STALE','BRANCH_BUDGET')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(campaign_id,root_key,state_hash,kind)
);

CREATE TABLE campaign_objects (
    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
    object_id TEXT NOT NULL REFERENCES test_objects(test_object_id),
    work_id TEXT NOT NULL REFERENCES campaign_work(work_id),
    cleanup_status TEXT NOT NULL CHECK(cleanup_status IN ('PENDING','CLEANED','ORPHANED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(campaign_id,object_id)
);
