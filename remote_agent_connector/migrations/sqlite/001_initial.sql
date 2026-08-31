CREATE TABLE IF NOT EXISTS remote_agent_devices (
    connector_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    display_label TEXT NOT NULL,
    capability_profile TEXT NOT NULL CHECK (
        capability_profile IN (
            'read_only',
            'read_write',
            'full_agent'
        )
    ),
    capabilities_json TEXT NOT NULL,
    enrollment_state TEXT NOT NULL CHECK (
        enrollment_state IN ('enrolled', 'revoked')
    ),
    enrolled_at TEXT NOT NULL,
    revoked_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    connector_id TEXT NOT NULL,
    capability_profile TEXT NOT NULL,
    display_label TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_challenges (
    challenge_id TEXT PRIMARY KEY,
    challenge_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_instances (
    instance_id TEXT PRIMARY KEY,
    connector_id TEXT NOT NULL,
    connection_generation TEXT NOT NULL,
    context_epoch INTEGER NOT NULL CHECK (context_epoch >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('online', 'offline')
    ),
    connected_at TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    disconnected_at TEXT,
    FOREIGN KEY (connector_id)
        REFERENCES remote_agent_devices(connector_id)
);

CREATE INDEX IF NOT EXISTS idx_remote_agent_live_instances_connector
ON live_instances(connector_id, state, last_heartbeat_at);

CREATE TABLE IF NOT EXISTS agent_requests (
    connector_id TEXT NOT NULL,
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
    PRIMARY KEY (connector_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS agent_audit_events (
    event_id TEXT PRIMARY KEY,
    agent_principal TEXT,
    connector_id TEXT,
    request_id TEXT,
    action TEXT NOT NULL,
    result_code TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
