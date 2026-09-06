-- Idempotency protects one caller against its own transport retry. The old key
-- was (connector_id, idempotency_key) with no caller, so a replay arriving
-- under a different client_id was served another caller's stored result.
--
-- The rebuild is additive: every existing row is carried over. client_id is
-- backfilled from the audit trail by request_id, which records the principal
-- that made the call. Rows with no attributable principal keep the empty
-- string, a value parse_client_id can never produce, so they stay as history
-- and cannot collide with a live caller.
CREATE TABLE agent_requests_new (
    connector_id TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'completed', 'failed')
    ),
    result_json TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY (connector_id, client_id, idempotency_key)
);

INSERT INTO agent_requests_new (
    connector_id, client_id, idempotency_key, request_id, tool_name,
    request_digest, status, result_json, created_at, completed_at
)
SELECT
    r.connector_id,
    COALESCE((
        SELECT a.agent_principal
        FROM agent_audit_events a
        WHERE a.request_id = r.request_id
          AND a.agent_principal IS NOT NULL
          AND a.agent_principal <> ''
        ORDER BY a.created_at ASC
        LIMIT 1
    ), ''),
    r.idempotency_key,
    r.request_id,
    r.tool_name,
    r.request_digest,
    r.status,
    r.result_json,
    r.created_at,
    r.completed_at
FROM agent_requests r;

DROP TABLE agent_requests;

ALTER TABLE agent_requests_new RENAME TO agent_requests;
