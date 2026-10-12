CREATE TABLE plan_message_dispatches_v19 (
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    step_id TEXT NOT NULL REFERENCES plan_run_steps(step_id),
    variant TEXT NOT NULL CHECK (variant IN ('NO_MESSAGE','WRONG_TYPE','TRUSTED',
        'UNRELATED','WRONG_SOURCE','NO_PORT','ATTACKER_PORT','FRESH_REPRODUCTION',
        'FRESH_WRONG_SOURCE','LOOKALIKE_ORIGIN','FRESH_LOOKALIKE_ORIGIN')),
    accounted_at TEXT NOT NULL,
    PRIMARY KEY(run_id,step_id,variant)
);
INSERT INTO plan_message_dispatches_v19 (run_id,step_id,variant,accounted_at)
    SELECT run_id,step_id,variant,accounted_at FROM plan_message_dispatches;
DROP TABLE plan_message_dispatches;
ALTER TABLE plan_message_dispatches_v19 RENAME TO plan_message_dispatches;
