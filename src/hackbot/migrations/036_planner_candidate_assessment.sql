CREATE TABLE planner_candidate_assessments (
    candidate_id TEXT PRIMARY KEY REFERENCES planner_candidates(candidate_id),
    assessment_json TEXT NOT NULL CHECK(length(assessment_json) <= 2048)
);

CREATE TRIGGER planner_candidate_assessments_no_update
BEFORE UPDATE ON planner_candidate_assessments
BEGIN SELECT RAISE(ABORT, 'candidate assessment is immutable'); END;

CREATE TRIGGER planner_candidate_assessments_no_delete
BEFORE DELETE ON planner_candidate_assessments
BEGIN SELECT RAISE(ABORT, 'candidate assessment is immutable'); END;
