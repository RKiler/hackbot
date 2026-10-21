CREATE TABLE registry_targets_replacement (
    target_id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    deleted_at TEXT
);

INSERT INTO registry_targets_replacement (target_id, package_id, registered_at, deleted_at)
SELECT r.target_id, r.package_id, r.registered_at,
       (SELECT max(e.occurred_at) FROM service_events AS e
        WHERE e.target_id = r.target_id AND e.event_type = 'target_deleted')
FROM registry_targets AS r;

DROP TABLE registry_targets;
ALTER TABLE registry_targets_replacement RENAME TO registry_targets;

CREATE UNIQUE INDEX registry_targets_active_package_id_idx
ON registry_targets(package_id) WHERE deleted_at IS NULL;
CREATE INDEX registry_targets_package_history_idx
ON registry_targets(package_id, registered_at);
