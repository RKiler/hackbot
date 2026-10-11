CREATE TABLE skill_plans (
    plan_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    skill_id TEXT NOT NULL,
    skill_version TEXT NOT NULL,
    skill_hash TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    manual_selection INTEGER NOT NULL CHECK (manual_selection IN (0,1)),
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    UNIQUE(hypothesis_id,skill_id,skill_version,skill_hash,generation)
);
CREATE INDEX skill_plans_target_idx ON skill_plans(target_id, created_at DESC);
CREATE INDEX skill_plans_hypothesis_idx ON skill_plans(hypothesis_id, created_at DESC);

CREATE TABLE skill_plan_selections (
    plan_id TEXT NOT NULL REFERENCES skill_plans(plan_id) ON DELETE RESTRICT,
    manual_selection INTEGER NOT NULL CHECK (manual_selection IN (0,1)),
    selected_at TEXT NOT NULL,
    PRIMARY KEY(plan_id, manual_selection)
);
