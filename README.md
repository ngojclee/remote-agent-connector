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

## Images

`publish-ghcr.yml` builds and pushes both production images to GHCR:

```text
ghcr.io/ngojclee/remote-agent-connector:latest      # /mcp connector
ghcr.io/ngojclee/remote-agent-connector:relay-latest # TLS WSS relay front
```

The relay image bakes `deploy/remote-agent-relay.nginx.conf`; only the TLS
certificate and key are mounted at runtime. Migrations install inside the
Python package, so no build tree needs to be bind-mounted into the container.
