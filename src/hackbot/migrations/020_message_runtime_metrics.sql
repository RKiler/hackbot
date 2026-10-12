ALTER TABLE message_analysis_runs ADD COLUMN sender_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE message_analysis_runs ADD COLUMN channel_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE message_runtime_trials (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence(evidence_id),
    target_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL REFERENCES message_protocol_candidates(candidate_id),
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    variant TEXT NOT NULL,
    message_count INTEGER NOT NULL CHECK (message_count BETWEEN 0 AND 3),
    port_count INTEGER NOT NULL CHECK (port_count BETWEEN 0 AND 1),
    rpc_calls INTEGER NOT NULL CHECK (rpc_calls BETWEEN 0 AND 1),
    capability_observed INTEGER NOT NULL CHECK (capability_observed IN (0,1)),
    recorded_at TEXT NOT NULL
);
CREATE INDEX message_runtime_trials_target ON message_runtime_trials(target_id,run_id);
