ALTER TABLE api_candidates ADD COLUMN behaviour_run_id TEXT REFERENCES behaviour_runs(run_id);
CREATE INDEX api_candidates_target_run ON api_candidates(target_id,run_id);
