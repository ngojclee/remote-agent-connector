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
REMOTE_AGENT_REQUEST_TIMEOUT_SECONDS=120   # 1-600
REMOTE_AGENT_RELAY_HANDSHAKE_TIMEOUT_SECONDS=15   # 1-60
```

Unset or `0` keeps Phase 2 in shadow mode: a v4 caller whose Hub has no signing
material still reaches the device with the Phase 1 statement object. Set `1`
only after the Hub publishes key material and the Windows lane verifies
cryptographically; then an unsigned v4 call fails closed.

## Two clocks

`REMOTE_AGENT_REQUEST_TIMEOUT_SECONDS` is the relay wait: how long the
connector holds a device call open before it reports `device_timeout`. It is
bounded at 600 seconds, and the only thing it has to fit inside is the Hub's
upstream read timeout. If the Hub gives up first, it returns a failure while the
device keeps executing the command, which is worse than a short ceiling.

The signed app assertion is a separate budget. A device judges freshness when
the request frame arrives, not when it produces the response, so the assertion
only has to outlive delivery from Hub to device. That is why the Hub can keep a
180 second assertion lifetime while the connector waits far longer for a slow
command. The two numbers were previously tied together, which capped legitimate
long commands at the assertion lifetime for no security gain.

The relay waits at most `REMOTE_AGENT_RELAY_HANDSHAKE_TIMEOUT_SECONDS` (15
seconds by default) for the first enrollment/authentication frame. This bound
does not apply to heartbeats or command responses. A client that reaches the
Python relay receives a fixed diagnostic with `error_contract`, `code`, `stage`,
`retryable`, and `message`; the payload never includes exception text, tokens,
public keys, signatures, challenge values, request bodies, credentials, or
filesystem paths. The stable contract is:

```text
relay_tls_failed          # local/client-side mapping; no relay frame exists
relay_upgrade_failed
relay_challenge_timeout
relay_challenge_invalid
enrollment_token_invalid
enrollment_token_expired
enrollment_token_consumed
connector_id_mismatch
enrollment_signature_invalid
enrollment_challenge_invalid
device_already_enrolled
device_revoked
relay_authentication_failed
relay_ready_failed
relay_protocol_error
```

An HTTP WebSocket upgrade or reverse-proxy failure happens before the Python
handler can send a relay frame. The baked Nginx front returns the bounded
`relay_upgrade_failed` JSON diagnostic instead. Transport TLS remains strict;
the timeout is not a TLS bypass.

The canonical error vocabulary is published in
`contracts/remote-agent-relay-errors-v1.json`. Python relay frames carry the
same `error_contract` identifier and the Nginx upgrade response carries it as
well. `relay_tls_failed` is transport-only: a certificate failure occurs
before HTTP/WebSocket application data exists, so the client or operator must
surface that code locally rather than expecting a relay error frame.
The operator can read the same closed vocabulary at
`GET /operator/relay-errors/v1` with the operator bearer.

## Operator CA publication

Set the optional path below to a public CA certificate mounted read-only into
the connector. The file must contain exactly one CA certificate with
`BasicConstraints CA=TRUE`; it must not contain a private key:

```text
REMOTE_AGENT_PUBLIC_CA_CERT_PATH=/etc/remote-agent/tls/remote-agent-ca.crt
```

An operator can read the versioned publication route with the existing
operator bearer:

```text
GET /operator/relay-ca/v1
```

The response contains only the normalized public certificate, SHA-256
fingerprint, subject/issuer and validity metadata. If the path is unset,
missing or invalid, the route returns a bounded `503` code:
`relay_ca_artifact_unconfigured`, `relay_ca_artifact_unavailable` or
`relay_ca_artifact_invalid`. The route is publication-only: neither the
connector nor a client auto-trusts a certificate fetched from it. Verify the
fingerprint out of band and install the CA explicitly on approved clients.

Two guards keep the separation honest:

- The connector refuses to send a frame whose assertion is already expired, as
  `app_assertion_expired_at_dispatch`. Delivering it would only earn a deny.
- A per-call `timeout_s` larger than the relay wait is refused as
  `timeout_exceeds_relay_window`, so a caller can never ask for a command the
  transport would abandon mid-run.

The device applies its own default when `timeout_s` is absent, so a caller that
needs a long command has to say so explicitly.

## In-flight collision guard

Transport retries must preserve the same `idempotency_key`. A same-key retry
with the same intent replays the first result, while the same key with a
different intent is refused as `idempotency_conflict`. A newly generated key is
a new operation, not a retry of the original operation.

The connector therefore holds a second guard keyed on the request content
instead: `(connector_id, tool, canonical digest of arguments)`, independent of
the caller's idempotency key. The window runs from dispatch until a terminal
response, a cancel, or the relay timeout. A second identical call inside that
window is refused with `command_in_flight`.

Guarded tools are the mutating ones: `files.write`, `files.delete`,
`files.move`, `files.mkdir`, `files.upload`, `terminal.execute`, `ssh.execute`,
`skills.materialize`, `skills.execute`, `mcp.call`. Read verbs are never
guarded, and nothing here dedups by arguments across time, so `git status`
before and after an edit both really run.

`command_in_flight` is a busy signal, not a permission failure and not a device
failure. It is safe to retry once the first call settles.

The connector forwards the existing key as the relay frame's top-level
`idempotency_key` field. It is not added to `arguments`, so the device receives
the same business argument shape and can apply its own replay protection before
dispatching a mutation.

## Cancel

`POST /operator/requests/{connector_id}/{request_id}/cancel` sends one cancel
frame over the device's existing relay WebSocket. It names a single `request_id`
and carries no arguments, no assertion and no authority, so it cannot reach
anything the original request did not already reach.

The connector resolves its own waiting caller with `cancelled` immediately and
frees that request's collision slot. A device that has not implemented cancel
ignores the frame, so this is safe to deploy before the Windows lane supports
it. The full wire contract lives in
`.docs/contracts/remote-agent-relay-control-v1.json`.

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
flag is unset, keep the application identity fields omitted. Every device call
still carries its existing `idempotency_key` as top-level relay metadata.

## Device liveness

Whether a device is online is derived from the age of its last heartbeat, not
from the stored `state` column. A row left behind by a crash, a container
restart, or a dropped relay therefore cannot be reported as live or routed to.

The window is five heartbeat intervals, so 75 seconds of silence at the current
15 second cadence. That is deliberately wider than
`REMOTE_AGENT_HEARTBEAT_TIMEOUT_SECONDS`, which is the transport timeout rather
than a liveness verdict: one lost packet or a short blip must not retire a
healthy session. If the configured timeout is larger than five intervals, the
configured value wins.

A sweep closes overdue rows by setting `state = 'offline'` and
`disconnected_at` to the last heartbeat, never to the sweep time, so a reaped
row stays distinguishable from a clean disconnect and never claims a device
outlived its silence. The sweep runs on every inventory and routing read.
