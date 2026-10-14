CREATE TABLE authorization_mutation_results_v32 (
    mutation_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    test_object_id TEXT NOT NULL REFERENCES test_objects(test_object_id),
    mutation_type TEXT NOT NULL CHECK (mutation_type IN ('RENAME','DELETE_DISPOSABLE')),
    phase TEXT NOT NULL CHECK (phase IN ('OWNER_CONTROL','BOUNDARY','RESTORE')),
    actor_identity_id TEXT NOT NULL REFERENCES registry_identities(identity_id),
    field TEXT NOT NULL CHECK ((mutation_type='RENAME' AND field='name') OR
                               (mutation_type='DELETE_DISPOSABLE' AND field='existence')),
    recipe_hash TEXT NOT NULL,
    expected_value_hash TEXT NOT NULL,
    before_value_hash TEXT,
    after_value_hash TEXT,
    mutation_action_id TEXT NOT NULL UNIQUE,
    mutation_exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    readback_action_id TEXT,
    readback_exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    status TEXT NOT NULL CHECK (status IN
        ('PLANNED','DISPATCHED','VERIFIED','DENIED','AMBIGUOUS','INSUFFICIENT_EVIDENCE')),
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id,test_object_id,phase)
);
INSERT INTO authorization_mutation_results_v32
SELECT * FROM authorization_mutation_results;
DROP TABLE authorization_mutation_results;
ALTER TABLE authorization_mutation_results_v32 RENAME TO authorization_mutation_results;
CREATE INDEX authorization_mutations_run ON authorization_mutation_results(run_id,created_at);
CREATE INDEX authorization_mutations_object ON authorization_mutation_results(test_object_id,created_at DESC);
CREATE INDEX authorization_mutations_target_status ON authorization_mutation_results(target_id,phase,status);
