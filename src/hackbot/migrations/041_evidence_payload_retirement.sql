CREATE TABLE evidence_payload_retirements (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence(evidence_id),
    retired_at TEXT NOT NULL,
    retention_class TEXT NOT NULL CHECK (retention_class IN ('REGENERABLE','EPHEMERAL')),
    actor TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TRIGGER evidence_payload_retirement_no_update
BEFORE UPDATE ON evidence_payload_retirements
BEGIN SELECT RAISE(ABORT, 'immutable evidence payload retirement'); END;

CREATE TRIGGER evidence_payload_retirement_no_delete
BEFORE DELETE ON evidence_payload_retirements
BEGIN SELECT RAISE(ABORT, 'immutable evidence payload retirement'); END;

CREATE TRIGGER evidence_payload_retirement_guard
BEFORE INSERT ON evidence_payload_retirements
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM evidence WHERE evidence_id=NEW.evidence_id
        AND content_kind='ARTIFACT'
    ) THEN RAISE(ABORT, 'only artifact Evidence can be retired') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM finding_evidence WHERE evidence_id=NEW.evidence_id
        UNION ALL SELECT 1 FROM finding_validation_evidence_holds
        WHERE evidence_id=NEW.evidence_id
    ) THEN RAISE(ABORT, 'finding Evidence cannot be retired') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM evidence_policy_events AS p
        WHERE p.evidence_id=NEW.evidence_id
        AND p.event_id=(SELECT max(event_id) FROM evidence_policy_events
                        WHERE evidence_id=NEW.evidence_id)
        AND (p.pinned=1 OR p.finding_related=1 OR
             (p.retain=1 AND (p.expires_at IS NULL OR p.expires_at>NEW.retired_at)))
    ) THEN RAISE(ABORT, 'retained Evidence cannot be retired') END;
END;

CREATE TRIGGER finding_evidence_no_retired_payload
BEFORE INSERT ON finding_evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked to a Finding'); END;

CREATE TRIGGER finding_validation_hold_no_retired_payload
BEFORE INSERT ON finding_validation_evidence_holds
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked to a Finding'); END;

CREATE TRIGGER evidence_policy_no_retain_retired_payload
BEFORE INSERT ON evidence_policy_events
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
AND (NEW.pinned=1 OR NEW.finding_related=1 OR NEW.retain=1)
BEGIN SELECT RAISE(ABORT, 'retired Evidence payload cannot be retained'); END;

CREATE TRIGGER retired_link_evidence_insert BEFORE INSERT ON evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.replaces_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_fact_evidence_insert BEFORE INSERT ON fact_evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_fact_status_insert BEFORE INSERT ON fact_status_events
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.supporting_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_auth_context_insert BEFORE INSERT ON auth_contexts
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_traffic_request_insert BEFORE INSERT ON traffic_requests
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id IN (NEW.body_evidence_id,NEW.observation_evidence_id))
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_traffic_response_insert BEFORE INSERT ON traffic_responses
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id IN (NEW.body_evidence_id,NEW.observation_evidence_id))
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_profile_source_insert BEFORE INSERT ON profile_source_evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_hypothesis_insert BEFORE INSERT ON hypothesis_evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_test_object_insert BEFORE INSERT ON test_objects
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.external_id_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_dom_js_insert BEFORE INSERT ON dom_js_artifacts
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_dom_map_insert BEFORE INSERT ON dom_source_maps
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_message_trial_insert BEFORE INSERT ON message_runtime_trials
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_exposure_source_insert BEFORE INSERT ON exposure_candidate_sources
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_bootstrap_insert BEFORE INSERT ON bootstrap_observations
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_behaviour_insert BEFORE INSERT ON behaviour_observations
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_api_operation_insert BEFORE INSERT ON api_operations
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.document_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_evidence_update BEFORE UPDATE OF replaces_evidence_id ON evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.replaces_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_fact_evidence_update BEFORE UPDATE OF evidence_id ON fact_evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_fact_status_update BEFORE UPDATE OF supporting_evidence_id ON fact_status_events
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.supporting_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_auth_context_update BEFORE UPDATE OF evidence_id ON auth_contexts
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_traffic_request_update BEFORE UPDATE OF body_evidence_id,observation_evidence_id ON traffic_requests
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id IN (NEW.body_evidence_id,NEW.observation_evidence_id))
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_traffic_response_update BEFORE UPDATE OF body_evidence_id,observation_evidence_id ON traffic_responses
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id IN (NEW.body_evidence_id,NEW.observation_evidence_id))
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_profile_source_update BEFORE UPDATE OF evidence_id ON profile_source_evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_hypothesis_update BEFORE UPDATE OF evidence_id ON hypothesis_evidence
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_test_object_update BEFORE UPDATE OF external_id_evidence_id ON test_objects
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.external_id_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_dom_js_update BEFORE UPDATE OF evidence_id ON dom_js_artifacts
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_dom_map_update BEFORE UPDATE OF evidence_id ON dom_source_maps
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_message_trial_update BEFORE UPDATE OF evidence_id ON message_runtime_trials
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_exposure_source_update BEFORE UPDATE OF evidence_id ON exposure_candidate_sources
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_bootstrap_update BEFORE UPDATE OF evidence_id ON bootstrap_observations
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_behaviour_update BEFORE UPDATE OF evidence_id ON behaviour_observations
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_link_api_operation_update BEFORE UPDATE OF document_evidence_id ON api_operations
WHEN EXISTS (SELECT 1 FROM evidence_payload_retirements
             WHERE evidence_id=NEW.document_evidence_id)
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;
CREATE TRIGGER retired_json_registry_principals_insert BEFORE INSERT ON registry_principals
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_principals_update BEFORE UPDATE OF evidence_ids_json ON registry_principals
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_tenants_insert BEFORE INSERT ON registry_tenants
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_tenants_update BEFORE UPDATE OF evidence_ids_json ON registry_tenants
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_roles_insert BEFORE INSERT ON registry_roles
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_roles_update BEFORE UPDATE OF evidence_ids_json ON registry_roles
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_identities_insert BEFORE INSERT ON registry_identities
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_identities_update BEFORE UPDATE OF evidence_ids_json ON registry_identities
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_principal_links_insert BEFORE INSERT ON registry_principal_links
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_principal_links_update BEFORE UPDATE OF evidence_ids_json ON registry_principal_links
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_memberships_insert BEFORE INSERT ON registry_memberships
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_registry_memberships_update BEFORE UPDATE OF evidence_ids_json ON registry_memberships
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_plan_step_results_insert BEFORE INSERT ON plan_step_results
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_plan_step_results_update BEFORE UPDATE OF evidence_ids_json ON plan_step_results
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_plan_step_manual_links_insert BEFORE INSERT ON plan_step_manual_links
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_plan_step_manual_links_update BEFORE UPDATE OF evidence_ids_json ON plan_step_manual_links
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_test_object_events_insert BEFORE INSERT ON test_object_events
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_test_object_events_update BEFORE UPDATE OF evidence_ids_json ON test_object_events
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_test_objects_insert BEFORE INSERT ON test_objects
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.creation_evidence_json) THEN NEW.creation_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
OR EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.verification_evidence_json) THEN NEW.verification_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
OR EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.cleanup_evidence_json) THEN NEW.cleanup_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_test_objects_update BEFORE UPDATE OF creation_evidence_json,verification_evidence_json,cleanup_evidence_json ON test_objects
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.creation_evidence_json) THEN NEW.creation_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
OR EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.verification_evidence_json) THEN NEW.verification_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
OR EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.cleanup_evidence_json) THEN NEW.cleanup_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_authorization_mutation_results_insert BEFORE INSERT ON authorization_mutation_results
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_authorization_mutation_results_update BEFORE UPDATE OF evidence_ids_json ON authorization_mutation_results
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_behaviour_workflows_insert BEFORE INSERT ON behaviour_workflows
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_behaviour_workflows_update BEFORE UPDATE OF evidence_ids_json ON behaviour_workflows
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_api_operations_insert BEFORE INSERT ON api_operations
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_api_operations_update BEFORE UPDATE OF evidence_ids_json ON api_operations
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_authorization_observations_insert BEFORE INSERT ON authorization_observations
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_authorization_observations_update BEFORE UPDATE OF evidence_ids_json ON authorization_observations
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_validation_checks_insert BEFORE INSERT ON validation_checks
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_validation_checks_update BEFORE UPDATE OF evidence_ids_json ON validation_checks
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.evidence_ids_json) THEN NEW.evidence_ids_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_validations_insert BEFORE INSERT ON validations
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.supporting_evidence_json) THEN NEW.supporting_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
OR EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.contradicting_evidence_json) THEN NEW.contradicting_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

CREATE TRIGGER retired_json_validations_update BEFORE UPDATE OF supporting_evidence_json,contradicting_evidence_json ON validations
WHEN EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.supporting_evidence_json) THEN NEW.supporting_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
OR EXISTS (SELECT 1 FROM json_tree(CASE WHEN json_valid(NEW.contradicting_evidence_json) THEN NEW.contradicting_evidence_json ELSE 'null' END) j JOIN evidence_payload_retirements r ON r.evidence_id=j.value WHERE j.type='text')
BEGIN SELECT RAISE(ABORT, 'retired Evidence cannot be linked'); END;

