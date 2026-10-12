ALTER TABLE message_candidate_assets RENAME TO message_candidate_assets_old;

CREATE TABLE message_candidate_assets (
    candidate_id TEXT NOT NULL REFERENCES message_protocol_candidates(candidate_id),
    artifact_id TEXT NOT NULL REFERENCES dom_js_artifacts(artifact_id),
    analysis_id TEXT NOT NULL REFERENCES message_analysis_runs(analysis_id),
    PRIMARY KEY(candidate_id, artifact_id, analysis_id)
);

INSERT INTO message_candidate_assets (candidate_id, artifact_id, analysis_id)
SELECT candidate_id, artifact_id, analysis_id FROM message_candidate_assets_old;

DROP TABLE message_candidate_assets_old;
CREATE INDEX message_candidate_assets_artifact ON message_candidate_assets(artifact_id,candidate_id);
