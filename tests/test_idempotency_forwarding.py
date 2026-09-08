"""Verify the server-tool to relay-frame idempotency boundary."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.protocol import capabilities_for_profile
from remote_agent_connector.relay import AgentRelaySession
from remote_agent_connector.server import create_app
from remote_agent_connector.store import RemoteAgentStore


SECRET = "d" * 48
MCP_TOKEN = "m" * 48
CONNECTOR = "agy2api-10.11.1.1"
IDEMPOTENCY_KEY = "owner-dry-run-20260908"


class _CapturingWebSocket:
    def __init__(self):
        self.sent: list[dict] = []
        self.session: AgentRelaySession | None = None

    async def send_json(self, message: dict) -> None:
        self.sent.append(message)
        future = self.session.pending.get(message["request_id"])
        if future is not None and not future.done():
            future.set_result(
                {
                    "code": "ok",
                    "dry_run": True,
                    "files": ["SKILL.md"],
                    "written": 0,
                }
            )


def _delegation_headers() -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = "n" * 24
    scopes = "agent:read,agent:skills,agent:write"
    payload = (
        f"v3\nremote-agent-connector\nagy2api\n{timestamp}\n"
        f"{nonce}\n{scopes}"
    )
    signature = hmac.new(
        SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "Authorization": f"Bearer {MCP_TOKEN}",
        "x-mcp-hub-client-id": "agy2api",
        "x-mcp-hub-client-scopes": scopes,
        "x-mcp-hub-client-nonce": nonce,
        "x-mcp-hub-client-timestamp": timestamp,
        "x-mcp-hub-client-signature": signature,
    }


class IdempotencyForwardingTests(unittest.TestCase):
    def _config(self, database_path: Path) -> RemoteAgentConfig:
        return RemoteAgentConfig(
            database_url=f"sqlite:///{database_path}",
            mcp_bearer_token=MCP_TOKEN,
            hub_delegation_secret=SECRET,
            operator_bearer_token="o" * 48,
            hub_audience="remote-agent-connector",
            private_mcp_url="http://127.0.0.1:3030/mcp",
            bind_host="127.0.0.1",
            bind_port=3030,
            allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
            allow_insecure_private_mcp=True,
            trust_proxy_tls=False,
            request_timeout_seconds=5,
            heartbeat_timeout_seconds=30,
        )

    async def _call_twice(self) -> list[dict]:
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = self._config(Path(temp_dir.name) / "server.sqlite")
            store = RemoteAgentStore(config.database_url)
            app = create_app(config, store)
            now = datetime.now(timezone.utc)
            self.assertTrue(
                store.enroll_device(
                    connector_id=CONNECTOR,
                    public_key="k" * 43,
                    display_label="Idempotency boundary",
                    capability_profile="full_agent",
                    platform="Windows 11",
                    now=now,
                )
            )
            self.assertTrue(
                store.upsert_presence(
                    connector_id=CONNECTOR,
                    instance_id="instance-01",
                    connection_generation="generation-01",
                    context_epoch=1,
                    capabilities=tuple(
                        capabilities_for_profile("full_agent")
                    ),
                    now=now,
                )
            )
            websocket = _CapturingWebSocket()
            session = AgentRelaySession(
                websocket=websocket,
                connector_id=CONNECTOR,
                instance_id="instance-01",
                context_epoch=1,
                connection_generation="generation-01",
                capabilities=tuple(
                    capabilities_for_profile("full_agent")
                ),
                capability_profile="full_agent",
            )
            websocket.session = session
            await app.state.remote_agent_relay_registry.register(session)

            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://127.0.0.1:3030",
                    headers=_delegation_headers(),
                ) as client:
                    async with streamable_http_client(
                        "http://127.0.0.1:3030/mcp",
                        http_client=client,
                    ) as (read, write, _):
                        async with ClientSession(read, write) as mcp:
                            await mcp.initialize()
                            arguments = {
                                "profile_id": CONNECTOR,
                                "idempotency_key": IDEMPOTENCY_KEY,
                                "skill_id": "hermes_agy2api_image_handling",
                                "target_root": "workspace",
                                # The handler keeps the business argument
                                # contract unchanged; the device defaults to
                                # dry-run when this is false/absent.
                                "apply": False,
                            }
                            first = await mcp.call_tool(
                                "skills_materialize", arguments
                            )
                            second = await mcp.call_tool(
                                "skills_materialize", arguments
                            )
                            self.assertFalse(first.isError)
                            self.assertFalse(second.isError)
            return websocket.sent
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()

    def test_server_tool_forwards_same_key_at_frame_boundary(self):
        frames = asyncio.run(self._call_twice())
        self.assertEqual(len(frames), 1)
        frame = frames[0]
        self.assertEqual(frame["idempotency_key"], IDEMPOTENCY_KEY)
        self.assertEqual(
            frame["arguments"],
            {
                "skill_id": "hermes_agy2api_image_handling",
                "target_root": "workspace",
            },
        )
        self.assertNotIn("apply", frame["arguments"])


if __name__ == "__main__":
    unittest.main()
