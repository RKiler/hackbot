CREATE TABLE auth_contexts (
    auth_context_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    mechanism TEXT NOT NULL CHECK (mechanism IN (
        'USERNAME_PASSWORD','COOKIE','BEARER','HEADER','LOGIN_FILE',
        'MANUAL_LOGIN','IMPORTED_SESSION','UNKNOWN')),
    status TEXT NOT NULL CHECK (status IN (
        'UNINITIALIZED','READY','VALID','EXPIRED','REAUTH_REQUIRED','INVALID','LOCKED','UNKNOWN')),
    preparation TEXT NOT NULL CHECK (preparation IN (
        'READY','MANUAL_LOGIN_REQUIRED','IMPORTED_SESSION_REFERENCE_AVAILABLE',
        'MISSING_SECRET','DISABLED','UNSUPPORTED_PROVIDER','UNKNOWN')),
    secret_ref TEXT,
    provider TEXT,
    browser_session_ref TEXT,
    csrf_metadata_ref TEXT,
    evidence_id TEXT REFERENCES evidence(evidence_id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    UNIQUE (target_id, identity_id),
    FOREIGN KEY (target_id, identity_id) REFERENCES registry_identities(target_id, identity_id)
);

CREATE INDEX auth_contexts_target_status_idx ON auth_contexts(target_id, status, identity_id);

CREATE TABLE auth_context_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_context_id TEXT NOT NULL REFERENCES auth_contexts(auth_context_id),
    event_type TEXT NOT NULL CHECK (event_type IN ('PREPARED','STATUS_CHANGED')),
    old_status TEXT,
    new_status TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);

CREATE INDEX auth_context_events_context_idx ON auth_context_events(auth_context_id, event_id);
