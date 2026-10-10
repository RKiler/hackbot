CREATE TABLE browser_sessions (
    session_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES registry_targets(target_id),
    identity_id TEXT REFERENCES registry_identities(identity_id),
    auth_context_id TEXT REFERENCES auth_contexts(auth_context_id),
    driver TEXT NOT NULL,
    profile_ref TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN (
        'CREATED','STARTING','RUNNING','WAITING_LOGIN','VERIFYING_IDENTITY',
        'NEEDS_MANUAL_REVIEW','VALID','EXPIRED','REAUTH_REQUIRED','FAILED','STOPPED')),
    verification_status TEXT NOT NULL CHECK (verification_status IN (
        'UNVERIFIED','MATCH','MISMATCH','UNKNOWN','EXPIRED')),
    proxy_enabled INTEGER NOT NULL CHECK (proxy_enabled IN (0,1)),
    proxy_ref TEXT,
    vnc_ref TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    last_verified_at TEXT,
    last_used_at TEXT,
    CHECK ((identity_id IS NULL AND auth_context_id IS NULL) OR
           (identity_id IS NOT NULL AND auth_context_id IS NOT NULL)),
    FOREIGN KEY (target_id, identity_id) REFERENCES registry_identities(target_id, identity_id)
);

CREATE INDEX browser_sessions_target_idx ON browser_sessions(target_id, created_at DESC, session_id DESC);
CREATE INDEX browser_sessions_identity_idx ON browser_sessions(target_id, identity_id, created_at DESC);

CREATE TABLE browser_session_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES browser_sessions(session_id),
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);

CREATE INDEX browser_session_events_session_idx ON browser_session_events(session_id, event_id);
