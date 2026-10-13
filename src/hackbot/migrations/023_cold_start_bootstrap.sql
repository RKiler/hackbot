CREATE TABLE bootstrap_runs (
    run_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('COLD_START','RECON_BACKED')),
    status TEXT NOT NULL CHECK (status IN ('CREATED','READY','RUNNING','WAITING_LOGIN','PARTIAL','COMPLETED','BLOCKED','FAILED','BUDGET_EXHAUSTED','CANCELLED')),
    identity_policy TEXT NOT NULL,
    identity_id TEXT,
    session_id TEXT,
    limits_json TEXT NOT NULL,
    counts_json TEXT NOT NULL,
    limitations_json TEXT NOT NULL,
    stop_reason TEXT,
    recon_domain_id INTEGER,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0,1))
);
CREATE INDEX bootstrap_runs_target_created ON bootstrap_runs(target_id, created_at DESC, run_id DESC);
CREATE UNIQUE INDEX bootstrap_runs_active_target ON bootstrap_runs(target_id)
    WHERE status IN ('CREATED','READY','RUNNING');

CREATE TABLE bootstrap_observations (
    observation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES bootstrap_runs(run_id),
    target_id TEXT NOT NULL,
    source TEXT NOT NULL,
    code TEXT NOT NULL,
    surface_key TEXT NOT NULL,
    display TEXT NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    source_ref TEXT,
    observed_at TEXT NOT NULL,
    UNIQUE(run_id,source,code,surface_key)
);
CREATE INDEX bootstrap_observations_target ON bootstrap_observations(target_id,observed_at DESC,observation_id DESC);

CREATE TABLE bootstrap_discovery_states (
    target_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('COLD_START','PARTIAL','BROWSER_PROFILED','TRAFFIC_PROFILED','RECON_BACKED','MATURE')),
    recon_domain_id INTEGER,
    last_run_id TEXT REFERENCES bootstrap_runs(run_id),
    updated_at TEXT NOT NULL
);
