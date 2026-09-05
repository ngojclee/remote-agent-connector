# Remote Agent Connector

Typed Remote Agent connector for Business MCP Hub using the VeilBrowser Fleet
pattern:

```text
Business MCP Hub -> remote-agent-mcp-connector (/mcp)
                 -> remote-agent-wss-relay (/relay)
                 -> client Remote Agent Connector
```

The connector service exposes 23 typed tools through Streamable HTTP MCP. It
also has a dedicated `/relay` endpoint for device WebSocket connections and a
SQLite device registry for capabilities, health, connection state, and
revocation.

Every tool handler is asynchronous and awaits the inner device command before
returning a JSON-ready object. MCP clients therefore receive a normal result or
MCP error envelope, never an unresolved coroutine.

## Required environment variables

```text
REMOTE_AGENT_DATABASE_URL=postgres://... or sqlite:///...
REMOTE_AGENT_MCP_BEARER_TOKEN=...
REMOTE_AGENT_HUB_DELEGATION_SECRET=...
REMOTE_AGENT_OPERATOR_BEARER_TOKEN=...
REMOTE_AGENT_HUB_AUDIENCE=remote-agent-connector
REMOTE_AGENT_PRIVATE_MCP_URL=http://remote-agent-mcp-connector:3030/mcp
REMOTE_AGENT_PUBLIC_RELAY_URL=wss://10.21.4.101:3051/relay
REMOTE_AGENT_BIND_HOST=0.0.0.0
REMOTE_AGENT_BIND_PORT=3030
REMOTE_AGENT_ALLOWED_HOSTS=remote-agent-mcp-connector:3030,127.0.0.1:3030,localhost:3030,10.21.4.101:3051
```

For local development only, set
`REMOTE_AGENT_ALLOW_SQLITE_DEV=1`, `REMOTE_AGENT_ALLOW_INSECURE_HTTP=1`, and
`REMOTE_AGENT_ALLOW_INSECURE_HTTP=1`.

Optional:

```text
REMOTE_AGENT_REQUIRE_SIGNED_ASSERTION=0
```

Unset or `0` keeps Phase 2 in shadow mode: a v4 caller whose Hub has no signing
material still reaches the device with the Phase 1 statement object. Set `1`
only after the Hub publishes key material and the Windows lane verifies
cryptographically; then an unsigned v4 call fails closed.

## Tool catalog

```text
connector_health
files_list
files_stat
files_search
files_read
files_write
files_delete
files_move
files_mkdir
files_upload
files_download
terminal_execute
terminal_stream
ssh_execute
ssh_list_profiles
skills_list
skills_materialize
skills_execute
mcp_list_servers
mcp_call
mcp_health
skills_health
connector_restart_mcp
```

The Hub exposes these as `agy_connector__<tool_name>`, which matches the
`agy_connector.*` tool contract used by agy2api. The connector id, audience,
service name, and environment variables stay `remote-agent` /
`REMOTE_AGENT_*`; only the MCP namespace carries the consumer-facing prefix.

## Authenticated agent status

The connector exposes an operator-only status route:

```text
GET http://remote-agent-mcp-connector:3030/agents
Authorization: Bearer <REMOTE_AGENT_OPERATOR_BEARER_TOKEN>
```

It returns only enrolled devices with a fresh online relay instance. Stale
instances are marked offline before the response. Each entry is sanitized to
`device_id`, `platform`, `capabilities`, `health`, and
`connected_at`; public keys, enrollment tokens, relay signatures, and
filesystem paths are never returned.

The private operator device inventory additionally returns the redacted
`public_key_fingerprint`, capability profile, enrollment state, and heartbeat
timestamps for Admin device management. It never returns the public key
material itself or any enrollment secret.

For all 23 MCP tools, agy2api passes the selected `device_id` as
`profile_id`. The connector resolves that value as the exact enrolled device
and optionally accepts `instance_id` to pin one live process. The capability
tier (`read_only`, `read_write`, or `full_agent`) is separate from
`profile_id`.

The public WSS endpoint is separate from MCP:

```text
wss://10.21.4.101:3051/relay
```

MCP remains authenticated Streamable HTTP at `/mcp`; WSS is only for device
relay traffic and is not a generic MCP-over-WebSocket transport.

## Images

`publish-ghcr.yml` builds and pushes both production images to GHCR:

```text
ghcr.io/ngojclee/remote-agent-connector:latest      # /mcp connector
ghcr.io/ngojclee/remote-agent-connector:relay-latest # TLS WSS relay front
```

The relay image bakes `deploy/remote-agent-relay.nginx.conf`; only the TLS
certificate and key are mounted at runtime. Migrations install inside the
Python package, so no build tree needs to be bind-mounted into the container.

## Windows pairing and revocation

Pairing is operator-controlled and one-time:

1. The operator calls `POST /operator/enrollment-tokens` with
   `connector_id`, `capability_profile` (`read_only`, `read_write`, or
   `full_agent`), `display_label`, and a short `expires_in_seconds` value.
2. The Windows connector opens the outbound WSS
   `wss://10.21.4.101:3051/relay`. The server sends a challenge. The client
   generates its Ed25519 key locally and sends the signed `enroll` payload
   containing the one-time enrollment token and its public key.
3. The server consumes both token and challenge, stores only the public-key
   identity and the approved capability profile, then issues a second
   challenge for normal authenticated relay operation.
4. The client signs the second challenge, receives `ready`, and sends
   heartbeats. The MCP connector routes every tool call by the exact
   `profile_id` supplied by agy2api, which is the enrolled device id.

Enrollment tokens, private keys, signatures, and operator bearer values are
never returned by `GET /agents` and must not be placed in logs or source
control. To revoke a device, the operator calls
`POST /operator/devices/{device_id}/revoke`; the connector immediately marks
the device revoked and closes its live instance. A revoked record may be
purged separately with `DELETE /operator/devices/{device_id}` after
revocation has been verified.

## Signed app assertions (Phase 2)

The Business MCP Hub is the only issuer of an application identity statement.
It signs a short-lived Ed25519 assertion per device call and sends it as
`X-MCP-Hub-App-Assertion`. The connector never holds the signing root, so it
cannot forge or edit the statement; it only:

1. parses the envelope strictly,
2. requires `client_id`, `app_id`, `scopes` and `nonce` to equal the HMAC
   identity it already verified,
3. requires `connector_id` to equal the call's `profile_id` target,
4. uses the envelope's `request_id` as the relay `request_id`, so the
   assertion is bound to exactly one frame,
5. forwards the envelope verbatim inside `app_assertion`.

`remote_agent_connector/app_assertion.py` is the reference device-side
verifier and the executable form of the contract: pinned root, keyset
verification, key-state and expiry checks, binding comparison, and replay
rejection. The Windows connector implements the same rules in Rust.

The shared byte-level vector lives in `tests/fixtures/app_assertion_vector.json`
and mirrors `.docs/contracts/app-identity-v2.json` in the Hub repository. Change
one and the other suite fails. Those keys are test-only and must never be used
as live signing material.

v3 callers, and v4 callers whose Hub has no signing material while the require
flag is unset, keep producing byte-identical relay frames.
