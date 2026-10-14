CREATE INDEX IF NOT EXISTS authorization_mutations_delete_exchange
ON authorization_mutation_results(target_id,mutation_exchange_id)
WHERE mutation_type='DELETE_DISPOSABLE' AND status='VERIFIED';

CREATE INDEX IF NOT EXISTS test_object_operations_cleanup_exchange
ON test_object_operations(exchange_id)
WHERE operation_kind='CLEANUP' AND status='SUCCEEDED';
