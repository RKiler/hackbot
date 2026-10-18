CREATE VIEW validation_evidence_refs AS
WITH linked AS (
    SELECT validation_id FROM findings
    UNION SELECT validation_id FROM finding_locations
    UNION SELECT validation_id FROM finding_duplicates
), refs AS (
    SELECT v.validation_id, v.supporting_evidence_json AS evidence_json
    FROM validations AS v JOIN linked AS l ON l.validation_id=v.validation_id
    UNION ALL
    SELECT v.validation_id, v.contradicting_evidence_json AS evidence_json
    FROM validations AS v JOIN linked AS l ON l.validation_id=v.validation_id
    UNION ALL
    SELECT c.validation_id, c.evidence_ids_json AS evidence_json
    FROM validation_checks AS c JOIN linked AS l ON l.validation_id=c.validation_id
)
SELECT r.validation_id,
       CASE WHEN j.type='text' THEN j.value ELSE NULL END AS evidence_id
FROM refs AS r, json_each(
    CASE WHEN json_valid(r.evidence_json) THEN
        CASE WHEN json_type(r.evidence_json)='array' THEN r.evidence_json
             ELSE '[null]' END
    ELSE '[null]' END
) AS j;

CREATE TABLE finding_validation_evidence_holds (
    evidence_id TEXT PRIMARY KEY NOT NULL REFERENCES evidence(evidence_id)
);

CREATE TRIGGER finding_validation_hold_no_update
BEFORE UPDATE ON finding_validation_evidence_holds
BEGIN SELECT RAISE(ABORT, 'immutable finding validation hold'); END;

CREATE TRIGGER finding_validation_hold_no_delete
BEFORE DELETE ON finding_validation_evidence_holds
BEGIN SELECT RAISE(ABORT, 'immutable finding validation hold'); END;

CREATE TRIGGER finding_validation_hold_policy
BEFORE INSERT ON evidence_policy_events
WHEN EXISTS (SELECT 1 FROM finding_validation_evidence_holds
             WHERE evidence_id=NEW.evidence_id)
 AND (NEW.retain<>1 OR NEW.pinned<>1 OR NEW.finding_related<>1
      OR NEW.expires_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'finding validation evidence must remain pinned'); END;

CREATE TRIGGER finding_validation_hold_pin
AFTER INSERT ON finding_validation_evidence_holds
BEGIN
    INSERT INTO evidence_policy_events
        (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
    SELECT NEW.evidence_id,1,NULL,1,1,
           strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),
           'finding_validation_link','finding_validation_evidence'
    WHERE NOT EXISTS (
        SELECT 1 FROM evidence_policy_events AS p
        WHERE p.event_id=(
            SELECT max(event_id) FROM evidence_policy_events
            WHERE evidence_id=NEW.evidence_id
        ) AND p.retain=1 AND p.pinned=1 AND p.finding_related=1
          AND p.expires_at IS NULL
    );
END;

INSERT INTO finding_validation_evidence_holds(evidence_id)
SELECT DISTINCT r.evidence_id FROM validation_evidence_refs AS r
WHERE r.validation_id IN (
    SELECT validation_id FROM findings
    UNION SELECT validation_id FROM finding_locations
    UNION SELECT validation_id FROM finding_duplicates
)
ON CONFLICT(evidence_id) DO NOTHING;

CREATE TRIGGER finding_validation_hold_primary
AFTER INSERT ON findings
BEGIN
    INSERT INTO finding_validation_evidence_holds(evidence_id)
    SELECT evidence_id FROM validation_evidence_refs
    WHERE validation_id=NEW.validation_id
    ON CONFLICT(evidence_id) DO NOTHING;
END;

CREATE TRIGGER finding_validation_hold_location
AFTER INSERT ON finding_locations
BEGIN
    INSERT INTO finding_validation_evidence_holds(evidence_id)
    SELECT evidence_id FROM validation_evidence_refs
    WHERE validation_id=NEW.validation_id
    ON CONFLICT(evidence_id) DO NOTHING;
END;

CREATE TRIGGER finding_validation_hold_duplicate
AFTER INSERT ON finding_duplicates
BEGIN
    INSERT INTO finding_validation_evidence_holds(evidence_id)
    SELECT evidence_id FROM validation_evidence_refs
    WHERE validation_id=NEW.validation_id
    ON CONFLICT(evidence_id) DO NOTHING;
END;

CREATE TRIGGER finding_validation_hold_late_check
AFTER INSERT ON validation_checks
WHEN EXISTS (SELECT 1 FROM findings WHERE validation_id=NEW.validation_id)
  OR EXISTS (SELECT 1 FROM finding_locations WHERE validation_id=NEW.validation_id)
  OR EXISTS (SELECT 1 FROM finding_duplicates WHERE validation_id=NEW.validation_id)
BEGIN
    INSERT INTO finding_validation_evidence_holds(evidence_id)
    SELECT evidence_id FROM validation_evidence_refs
    WHERE validation_id=NEW.validation_id
    ON CONFLICT(evidence_id) DO NOTHING;
END;
