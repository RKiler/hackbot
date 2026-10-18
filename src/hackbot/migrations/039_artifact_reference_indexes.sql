CREATE INDEX IF NOT EXISTS evidence_artifact_hash_lookup
    ON evidence(artifact_hash) WHERE artifact_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS traffic_requests_artifact_hash_lookup
    ON traffic_requests(artifact_hash) WHERE artifact_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS traffic_responses_artifact_hash_lookup
    ON traffic_responses(artifact_hash) WHERE artifact_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS plan_step_results_artifact_hash_lookup
    ON plan_step_results(artifact_hash) WHERE artifact_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS dom_js_artifacts_hash_lookup
    ON dom_js_artifacts(artifact_sha256);
CREATE INDEX IF NOT EXISTS dom_source_maps_hash_lookup
    ON dom_source_maps(map_sha256);
CREATE INDEX IF NOT EXISTS exposure_candidate_sources_hash_lookup
    ON exposure_candidate_sources(artifact_sha256)
    WHERE artifact_sha256 IS NOT NULL;

-- Traffic retirement checks these direct links for every candidate exchange.
CREATE INDEX IF NOT EXISTS api_candidates_owner_exchange_lookup
    ON api_candidates(owner_exchange_id) WHERE owner_exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS authorization_candidates_owner_exchange_lookup
    ON authorization_candidates(owner_exchange_id);
CREATE INDEX IF NOT EXISTS authorization_mutations_exchange_lookup
    ON authorization_mutation_results(mutation_exchange_id)
    WHERE mutation_exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS authorization_mutations_readback_exchange_lookup
    ON authorization_mutation_results(readback_exchange_id)
    WHERE readback_exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS authorization_observations_exchange_lookup
    ON authorization_observations(exchange_id) WHERE exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dom_js_artifacts_retrieval_exchange_lookup
    ON dom_js_artifacts(retrieval_exchange_id)
    WHERE retrieval_exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dom_source_maps_retrieval_exchange_lookup
    ON dom_source_maps(retrieval_exchange_id)
    WHERE retrieval_exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS executor_events_exchange_lookup
    ON executor_events(exchange_id) WHERE exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS test_object_events_exchange_lookup
    ON test_object_events(exchange_id) WHERE exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS test_object_operations_exchange_lookup
    ON test_object_operations(exchange_id) WHERE exchange_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS test_objects_creation_exchange_lookup
    ON test_objects(creation_exchange_id) WHERE creation_exchange_id IS NOT NULL;
