-- A finding link is a durable hold even when the specialist did not set one.
INSERT INTO evidence_policy_events
    (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
SELECT fe.evidence_id,1,NULL,1,1,
       strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),
       'finding_evidence_migration','existing_finding_link'
FROM (SELECT DISTINCT evidence_id FROM finding_evidence) AS fe
WHERE NOT EXISTS (
    SELECT 1 FROM evidence_policy_events AS p
    WHERE p.event_id=(
        SELECT max(event_id) FROM evidence_policy_events
        WHERE evidence_id=fe.evidence_id
    ) AND p.retain=1 AND p.pinned=1 AND p.finding_related=1
      AND p.expires_at IS NULL
);

CREATE TRIGGER evidence_finding_hold BEFORE INSERT ON evidence_policy_events
WHEN EXISTS (SELECT 1 FROM finding_evidence WHERE evidence_id=NEW.evidence_id)
 AND (NEW.retain<>1 OR NEW.pinned<>1 OR NEW.finding_related<>1
      OR NEW.expires_at IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'finding evidence must remain pinned'); END;

CREATE TRIGGER finding_evidence_pin AFTER INSERT ON finding_evidence
BEGIN
    INSERT INTO evidence_policy_events
        (evidence_id,retain,expires_at,pinned,finding_related,changed_at,actor,reason)
    SELECT NEW.evidence_id,1,NULL,1,1,
           strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),
           'finding_evidence_link','confirmed_finding_link'
    WHERE NOT EXISTS (
        SELECT 1 FROM evidence_policy_events AS p
        WHERE p.event_id=(
            SELECT max(event_id) FROM evidence_policy_events
            WHERE evidence_id=NEW.evidence_id
        ) AND p.retain=1 AND p.pinned=1 AND p.finding_related=1
          AND p.expires_at IS NULL
    );
END;
