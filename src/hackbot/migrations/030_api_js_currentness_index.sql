CREATE INDEX api_js_artifacts_target_hash_state
    ON dom_js_artifacts(target_id,artifact_sha256,state);
