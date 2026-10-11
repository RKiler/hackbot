ALTER TABLE browser_sessions ADD COLUMN proxy_capture_required INTEGER NOT NULL DEFAULT 0
    CHECK (proxy_capture_required IN (0,1));

CREATE TABLE burp_projects (
    target_id TEXT PRIMARY KEY REFERENCES registry_targets(target_id),
    package_id TEXT NOT NULL,
    project_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE burp_listener_bindings (
    binding_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    browser_session_id TEXT NOT NULL UNIQUE REFERENCES browser_sessions(session_id),
    listener_key TEXT NOT NULL,
    proxy_port INTEGER NOT NULL CHECK (proxy_port BETWEEN 1024 AND 65535),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','RELEASED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX burp_listener_active_key_idx
    ON burp_listener_bindings(listener_key) WHERE state='ACTIVE';
CREATE UNIQUE INDEX burp_listener_active_port_idx
    ON burp_listener_bindings(proxy_port) WHERE state='ACTIVE';
CREATE INDEX burp_listener_target_idx
    ON burp_listener_bindings(target_id,state,created_at DESC,binding_id DESC);

CREATE TABLE burp_capture_index (
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    capture_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    response_digest TEXT,
    listener_key TEXT NOT NULL,
    exchange_id TEXT REFERENCES traffic_exchanges(exchange_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (target_id,capture_id)
);
CREATE INDEX burp_capture_exchange_idx ON burp_capture_index(exchange_id);

CREATE TABLE burp_bridge_health (
    target_id TEXT PRIMARY KEY REFERENCES registry_targets(target_id),
    bridge_version TEXT NOT NULL,
    dropped_events INTEGER NOT NULL DEFAULT 0 CHECK (dropped_events >= 0),
    last_seen_at TEXT NOT NULL
);

CREATE UNIQUE INDEX traffic_burp_provider_reference_idx
    ON traffic_exchanges(target_id,provider_reference_hash)
    WHERE source='BURP' AND provider_reference_hash IS NOT NULL;
