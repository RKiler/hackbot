CREATE TABLE api_inventory_progress (
    target_id TEXT PRIMARY KEY REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    traffic_cursor TEXT,
    js_cursor TEXT,
    operation_cursor TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS dom_js_artifacts_target_current_page
    ON dom_js_artifacts(target_id,state,retrieved_at DESC,artifact_id DESC);
