ALTER TABLE api_candidates ADD COLUMN child_object_id TEXT REFERENCES test_objects(test_object_id);
