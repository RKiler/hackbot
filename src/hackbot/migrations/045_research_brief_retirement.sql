CREATE TABLE research_brief_payload_retirements (
    brief_id TEXT PRIMARY KEY REFERENCES research_briefs(brief_id),
    retired_at TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes>2),
    reason TEXT NOT NULL CHECK(reason='reviewed-expired-cache')
);
CREATE INDEX research_briefs_expiry_lookup ON research_briefs(expires_at,brief_id);
CREATE INDEX research_requests_brief_status ON research_requests(brief_id,status)
    WHERE brief_id IS NOT NULL;
CREATE INDEX planner_tasks_research_result ON planner_tasks(result_ref)
    WHERE result_ref IS NOT NULL;

CREATE TABLE planner_candidate_research_refs (
    candidate_id TEXT NOT NULL REFERENCES planner_candidates(candidate_id),
    brief_id TEXT NOT NULL REFERENCES research_briefs(brief_id),
    PRIMARY KEY(candidate_id,brief_id)
);
CREATE INDEX planner_candidate_research_refs_brief
    ON planner_candidate_research_refs(brief_id,candidate_id);
INSERT OR IGNORE INTO planner_candidate_research_refs(candidate_id,brief_id)
SELECT c.candidate_id,b.brief_id FROM planner_candidates c,
     json_each(c.source_refs_json) j JOIN research_briefs b ON b.brief_id=j.value;

CREATE TABLE planner_event_research_refs (
    event_id INTEGER NOT NULL REFERENCES planner_events(event_id),
    brief_id TEXT NOT NULL REFERENCES research_briefs(brief_id),
    PRIMARY KEY(event_id,brief_id)
);
CREATE INDEX planner_event_research_refs_brief
    ON planner_event_research_refs(brief_id,event_id);
INSERT OR IGNORE INTO planner_event_research_refs(event_id,brief_id)
SELECT e.event_id,b.brief_id FROM planner_events e,
     json_each(e.safe_refs_json) j JOIN research_briefs b ON b.brief_id=j.value;

CREATE TRIGGER research_ref_candidate_insert_guard BEFORE INSERT ON planner_candidates
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM research_brief_payload_retirements r,
             json_each(NEW.source_refs_json) j WHERE j.value=r.brief_id
    ) THEN RAISE(ABORT,'retired research brief') END;
END;
CREATE TRIGGER research_ref_candidate_update_guard BEFORE UPDATE OF source_refs_json ON planner_candidates
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM research_brief_payload_retirements r,
             json_each(NEW.source_refs_json) j WHERE j.value=r.brief_id
    ) THEN RAISE(ABORT,'retired research brief') END;
END;
CREATE TRIGGER research_ref_candidate_insert AFTER INSERT ON planner_candidates
BEGIN
    INSERT OR IGNORE INTO planner_candidate_research_refs(candidate_id,brief_id)
    SELECT NEW.candidate_id,b.brief_id FROM json_each(NEW.source_refs_json) j
    JOIN research_briefs b ON b.brief_id=j.value;
END;
CREATE TRIGGER research_ref_candidate_update AFTER UPDATE OF source_refs_json ON planner_candidates
BEGIN
    DELETE FROM planner_candidate_research_refs WHERE candidate_id=NEW.candidate_id;
    INSERT OR IGNORE INTO planner_candidate_research_refs(candidate_id,brief_id)
    SELECT NEW.candidate_id,b.brief_id FROM json_each(NEW.source_refs_json) j
    JOIN research_briefs b ON b.brief_id=j.value;
END;
CREATE TRIGGER research_ref_candidate_delete AFTER DELETE ON planner_candidates
BEGIN
    DELETE FROM planner_candidate_research_refs WHERE candidate_id=OLD.candidate_id;
END;

CREATE TRIGGER research_ref_event_insert_guard BEFORE INSERT ON planner_events
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM research_brief_payload_retirements r,
             json_each(NEW.safe_refs_json) j WHERE j.value=r.brief_id
    ) THEN RAISE(ABORT,'retired research brief') END;
END;
CREATE TRIGGER research_ref_event_insert AFTER INSERT ON planner_events
BEGIN
    INSERT OR IGNORE INTO planner_event_research_refs(event_id,brief_id)
    SELECT NEW.event_id,b.brief_id FROM json_each(NEW.safe_refs_json) j
    JOIN research_briefs b ON b.brief_id=j.value;
END;

CREATE TRIGGER research_ref_hypothesis_insert BEFORE INSERT ON research_hypothesis_links
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.brief_id)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_ref_hypothesis_update BEFORE UPDATE OF brief_id ON research_hypothesis_links
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.brief_id)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_ref_proposal_insert BEFORE INSERT ON research_skill_proposals
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.brief_id)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_ref_proposal_update BEFORE UPDATE OF brief_id ON research_skill_proposals
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.brief_id)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_ref_task_insert BEFORE INSERT ON planner_tasks
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.result_ref)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_ref_task_update BEFORE UPDATE OF result_ref ON planner_tasks
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.result_ref)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_ref_request_insert BEFORE INSERT ON research_requests
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.brief_id)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_ref_request_update BEFORE UPDATE OF brief_id ON research_requests
WHEN NEW.brief_id IS NOT OLD.brief_id AND
     EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.brief_id)
BEGIN SELECT RAISE(ABORT,'retired research brief'); END;
CREATE TRIGGER research_retirement_guard BEFORE INSERT ON research_brief_payload_retirements
WHEN (SELECT payload_json FROM research_briefs WHERE brief_id=NEW.brief_id)!='{}'
BEGIN SELECT RAISE(ABORT,'research brief payload is not retired'); END;
CREATE TRIGGER research_retirement_no_update BEFORE UPDATE ON research_brief_payload_retirements
BEGIN SELECT RAISE(ABORT,'research retirement is immutable'); END;
CREATE TRIGGER research_retirement_no_delete BEFORE DELETE ON research_brief_payload_retirements
BEGIN SELECT RAISE(ABORT,'research retirement is immutable'); END;
CREATE TRIGGER research_payload_no_rewrite BEFORE UPDATE OF payload_json ON research_briefs
WHEN EXISTS (SELECT 1 FROM research_brief_payload_retirements WHERE brief_id=NEW.brief_id)
BEGIN SELECT RAISE(ABORT,'research brief payload is retired'); END;
