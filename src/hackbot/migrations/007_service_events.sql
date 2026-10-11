CREATE TABLE service_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    target_id TEXT,
    identity_id TEXT,
    session_id TEXT
);
CREATE INDEX idx_service_events_recent ON service_events(id DESC);
