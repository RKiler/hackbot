CREATE TABLE traffic_payload_retirements (
    exchange_id TEXT PRIMARY KEY REFERENCES traffic_exchanges(exchange_id),
    request_id TEXT NOT NULL UNIQUE REFERENCES traffic_requests(request_id),
    response_id TEXT UNIQUE REFERENCES traffic_responses(response_id),
    retired_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TRIGGER traffic_payload_retirement_no_update
BEFORE UPDATE ON traffic_payload_retirements
BEGIN SELECT RAISE(ABORT, 'immutable traffic payload retirement'); END;

CREATE TRIGGER traffic_payload_retirement_no_delete
BEFORE DELETE ON traffic_payload_retirements
BEGIN SELECT RAISE(ABORT, 'immutable traffic payload retirement'); END;

CREATE TRIGGER traffic_payload_retirement_guard
BEFORE INSERT ON traffic_payload_retirements
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM traffic_exchanges e
        WHERE e.exchange_id=NEW.exchange_id AND e.request_id=NEW.request_id
          AND e.state IN ('COMPLETE','FAILED','ABORTED','TIMEOUT')
          AND e.pinned=0 AND e.finding_related=0
          AND (e.retain=0 OR (e.expires_at IS NOT NULL
                              AND e.expires_at<=NEW.retired_at))
          AND ((e.state='COMPLETE' AND EXISTS (
                  SELECT 1 FROM traffic_responses r
                  WHERE r.request_id=e.request_id AND r.response_id=NEW.response_id))
               OR (e.state<>'COMPLETE' AND NEW.response_id IS NULL AND NOT EXISTS (
                  SELECT 1 FROM traffic_responses r WHERE r.request_id=e.request_id)))
    ) THEN RAISE(ABORT, 'ineligible traffic payload retirement') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM traffic_requests q WHERE q.request_id=NEW.request_id
        AND (NOT EXISTS (SELECT 1 FROM evidence_payload_retirements p
                         WHERE p.evidence_id=q.observation_evidence_id)
             OR (q.body_evidence_id IS NOT NULL AND NOT EXISTS (
                 SELECT 1 FROM evidence_payload_retirements p
                 WHERE p.evidence_id=q.body_evidence_id)))
    ) THEN RAISE(ABORT, 'traffic Evidence is not retired') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM traffic_responses r WHERE r.request_id=NEW.request_id
        AND (NOT EXISTS (SELECT 1 FROM evidence_payload_retirements p
                         WHERE p.evidence_id=r.observation_evidence_id)
             OR (r.body_evidence_id IS NOT NULL AND NOT EXISTS (
                 SELECT 1 FROM evidence_payload_retirements p
                 WHERE p.evidence_id=r.body_evidence_id)))
    ) THEN RAISE(ABORT, 'traffic Evidence is not retired') END;
END;
