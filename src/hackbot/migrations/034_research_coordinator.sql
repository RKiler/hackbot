CREATE TABLE IF NOT EXISTS research_requests (
    request_id TEXT PRIMARY KEY,
    target_id TEXT REFERENCES registry_targets(target_id),
    gap_ref TEXT NOT NULL,
    gap_type TEXT NOT NULL,
    topic TEXT NOT NULL,
    technology TEXT,
    security_category TEXT,
    specialist TEXT NOT NULL,
    hypothesis_id TEXT REFERENCES hypotheses(hypothesis_id),
    cache_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN
        ('PENDING','CACHE_HIT','RESEARCHING','COMPLETED','PARTIAL','FAILED','BLOCKED','STALE','CANCELLED')),
    budget_json TEXT NOT NULL,
    external_allowed INTEGER NOT NULL CHECK(external_allowed IN (0,1)),
    private_target INTEGER NOT NULL CHECK(private_target IN (0,1)),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
    brief_id TEXT,
    error_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    usage_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS research_requests_target_recent ON research_requests(target_id,created_at DESC,request_id DESC);
CREATE INDEX IF NOT EXISTS research_requests_cache ON research_requests(cache_key,status,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS research_one_active_gap ON research_requests(cache_key,target_id)
    WHERE status IN ('PENDING','RESEARCHING');

CREATE TABLE IF NOT EXISTS research_briefs (
    brief_id TEXT PRIMARY KEY,
    cache_key TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    content_hash TEXT NOT NULL,
    topic TEXT NOT NULL,
    target_id TEXT REFERENCES registry_targets(target_id),
    summary TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    quality INTEGER NOT NULL CHECK(quality BETWEEN 0 AND 100),
    retrieved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_from_request TEXT NOT NULL REFERENCES research_requests(request_id),
    UNIQUE(cache_key,version)
);
CREATE INDEX IF NOT EXISTS research_briefs_cache ON research_briefs(cache_key,version DESC);
CREATE INDEX IF NOT EXISTS research_briefs_target_recent ON research_briefs(target_id,retrieved_at DESC,brief_id DESC);

CREATE TABLE IF NOT EXISTS research_sources (
    source_id TEXT PRIMARY KEY,
    canonical_url TEXT,
    source_type TEXT NOT NULL,
    title TEXT NOT NULL,
    publisher TEXT NOT NULL,
    published_at TEXT,
    retrieved_at TEXT NOT NULL,
    quality INTEGER NOT NULL CHECK(quality BETWEEN 0 AND 100),
    fingerprint TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS research_brief_sources (
    brief_id TEXT NOT NULL REFERENCES research_briefs(brief_id),
    source_id TEXT NOT NULL REFERENCES research_sources(source_id),
    retrieved_at TEXT NOT NULL,
    PRIMARY KEY(brief_id,source_id)
);
CREATE TABLE IF NOT EXISTS research_skill_proposals (
    proposal_id TEXT PRIMARY KEY,
    brief_id TEXT NOT NULL REFERENCES research_briefs(brief_id),
    name TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ADVISORY','REVIEWED','REJECTED')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS research_hypothesis_links (
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(hypothesis_id),
    brief_id TEXT NOT NULL REFERENCES research_briefs(brief_id),
    guidance_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(hypothesis_id,brief_id)
);
