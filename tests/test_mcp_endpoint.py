from __future__ import annotations

import asyncio
import base64
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from starlette.testclient import TestClient

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.relay import AgentRelayEndpoint, AgentRelaySession
from remote_agent_connector.server import create_app
from remote_agent_connector.store import RemoteAgentStore


class RemoteAgentEndpointTests(unittest.TestCase):
    def test_mcp_catalog_is_typed_and_closed(self):
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = RemoteAgentConfig(
                database_url=f"sqlite:///{Path(temp_dir.name) / 'remote-agent.sqlite'}",
                mcp_bearer_token="m" * 48,
                hub_delegation_secret="d" * 48,
                operator_bearer_token="o" * 48,
                hub_audience="remote-agent-connector",
                private_mcp_url="http://127.0.0.1:3030/mcp",
                bind_host="127.0.0.1",
                bind_port=3030,
                allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
                allow_insecure_private_mcp=True,
                trust_proxy_tls=False,
                request_timeout_seconds=2,
                heartbeat_timeout_seconds=2,
            )
            store = RemoteAgentStore(config.database_url)
            app = create_app(config, store)
            tools = asyncio.run(app.state.mcp_server.list_tools())
            self.assertEqual(
                {tool.name for tool in tools},
                {
                    "connector_health",
                    "files_list",
                    "files_stat",
                    "files_search",
                    "files_read",
                    "files_write",
                    "files_delete",
                    "files_move",
                    "files_mkdir",
                    "files_upload",
                    "files_download",
                    "terminal_execute",
                    "terminal_stream",
                    "ssh_execute",
                    "ssh_list_profiles",
                    "skills_list",
                    "skills_materialize",
                    "skills_execute",
                    "mcp_list_servers",
                    "mcp_call",
                    "mcp_health",
                    "skills_health",
                    "connector_restart_mcp",
                },
            )
            for tool in tools:
                properties = tool.inputSchema.get("properties", {})
                required = tool.inputSchema.get("required", [])
                self.assertIn("profile_id", properties, tool.name)
                self.assertIn("profile_id", required, tool.name)
                self.assertNotIn("connector_id", properties, tool.name)
            tool_manager = app.state.mcp_server._tool_manager
            registered = tool_manager._tools
            self.assertEqual(
                set(registered),
                {
                    "connector_health",
                    "files_list",
                    "files_stat",
                    "files_search",
                    "files_read",
                    "files_write",
                    "files_delete",
                    "files_move",
                    "files_mkdir",
                    "files_upload",
                    "files_download",
                    "terminal_execute",
                    "terminal_stream",
                    "ssh_execute",
                    "ssh_list_profiles",
                    "skills_list",
                    "skills_materialize",
                    "skills_execute",
                    "mcp_list_servers",
                    "mcp_call",
                    "mcp_health",
                    "skills_health",
                    "connector_restart_mcp",
                },
            )
            # Every handler must await the inner agent call. A sync handler
            # that returns the coroutine leaks "<coroutine object>" to MCP
            # clients instead of a dict result.
            non_async = [
                name
                for name, tool in registered.items()
                if not getattr(tool, "is_async", False)
            ]
            self.assertEqual(non_async, [])
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()

    def test_legacy_database_bootstraps_migration_history(self):
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            database_path = Path(temp_dir.name) / "legacy.sqlite"
            initial_sql = (
                Path(__file__).resolve().parents[1]
                / "remote_agent_connector"
                / "migrations"
                / "sqlite"
                / "001_initial.sql"
            ).read_text(encoding="utf-8")
            connection = sqlite3.connect(database_path)
            connection.executescript(initial_sql)
            connection.close()

            store = RemoteAgentStore(f"sqlite:///{database_path}")
            columns = {
                row[1]
                for row in store._connection.execute(
                    "PRAGMA table_info(remote_agent_devices)"
                ).fetchall()
            }
            self.assertIn("platform", columns)
            versions = {
                row[0]
                for row in store._connection.execute(
                    "SELECT version FROM schema_migrations"
                ).fetchall()
            }
            self.assertEqual(
                versions,
                {"001_initial.sql", "002_platform.sql"},
            )
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()

    def test_authenticated_agents_returns_sanitized_online_devices(self):
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = RemoteAgentConfig(
                database_url=f"sqlite:///{Path(temp_dir.name) / 'remote-agent.sqlite'}",
                mcp_bearer_token="m" * 48,
                hub_delegation_secret="d" * 48,
                operator_bearer_token="o" * 48,
                hub_audience="remote-agent-connector",
                private_mcp_url="http://127.0.0.1:3030/mcp",
                bind_host="127.0.0.1",
                bind_port=3030,
                allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
                allow_insecure_private_mcp=True,
                trust_proxy_tls=False,
                request_timeout_seconds=2,
                heartbeat_timeout_seconds=30,
            )
            store = RemoteAgentStore(config.database_url)
            now = datetime.now(timezone.utc)
            self.assertTrue(
                store.enroll_device(
                    connector_id="windows-01",
                    public_key=base64.urlsafe_b64encode(
                        b"k" * 32
                    ).decode("ascii").rstrip("="),
                    display_label="Windows 01",
                    capability_profile="read_only",
                    platform="Windows 11",
                    now=now,
                )
            )
            self.assertTrue(
                store.upsert_presence(
                    connector_id="windows-01",
                    instance_id="instance-01",
                    connection_generation="generation-01",
                    context_epoch=1,
                    capabilities=(
                        "connector_health",
                        "files_list",
                        "files_read",
                    ),
                    now=now,
                )
            )
            app = create_app(config, store)
            with TestClient(app) as client:
                request_headers = {"Host": "localhost:3030"}
                unauthorized = client.get(
                    "/agents",
                    headers=request_headers,
                )
                self.assertEqual(unauthorized.status_code, 401)

                response = client.get(
                    "/agents",
                    headers={
                        **request_headers,
                        "Authorization": "Bearer "
                        + config.operator_bearer_token
                    },
                )
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertEqual(payload["count"], 1)
                self.assertEqual(
                    set(payload["agents"][0]),
                    {
                        "device_id",
                        "platform",
                        "capabilities",
                        "health",
                        "connected_at",
                    },
                )
                self.assertEqual(
                    payload["agents"][0]["device_id"],
                    "windows-01",
                )
                self.assertEqual(
                    payload["agents"][0]["platform"],
                    "Windows 11",
                )
                self.assertEqual(
                    payload["agents"][0]["health"],
                    "online",
                )
                self.assertNotIn(
                    "public_key",
                    payload["agents"][0],
                )
                self.assertNotIn(
                    "enrollment_token",
                    payload["agents"][0],
                )
                operator_devices = client.get(
                    "/operator/devices",
                    headers={
                        **request_headers,
                        "Authorization": "Bearer "
                        + config.operator_bearer_token
                    },
                )
                self.assertEqual(operator_devices.status_code, 200)
                device = operator_devices.json()["devices"][0]
                self.assertRegex(
                    device["public_key_fingerprint"],
                    r"^[0-9a-f]{16}$",
                )
                self.assertNotIn("public_key", device)
                self.assertNotIn("enrollment_token", device)
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()

    def test_relay_endpoint_is_asgi_callable_and_accepts_websocket(self):
        temp_dir = tempfile.TemporaryDirectory()
        try:
            config = RemoteAgentConfig(
                database_url=f"sqlite:///{Path(temp_dir.name) / 'remote-agent.sqlite'}",
                mcp_bearer_token="m" * 48,
                hub_delegation_secret="d" * 48,
                operator_bearer_token="o" * 48,
                hub_audience="remote-agent-connector",
                private_mcp_url="http://127.0.0.1:3030/mcp",
                bind_host="127.0.0.1",
                bind_port=3030,
                allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
                allow_insecure_private_mcp=True,
                trust_proxy_tls=True,
                request_timeout_seconds=2,
                heartbeat_timeout_seconds=30,
            )
            store = RemoteAgentStore(config.database_url)
            app = create_app(config, store)
            with TestClient(app) as client:
                with client.websocket_connect(
                    "/relay",
                    headers={
                        "Host": "localhost:3030",
                        "X-Forwarded-Proto": "https",
                    },
                ) as websocket:
                    message = websocket.receive_json()
            self.assertEqual(message["type"], "challenge")
            self.assertTrue(message["challenge"])
            self.assertTrue(message["challenge_id"])
        finally:
            store.close()
            temp_dir.cleanup()

    def test_relay_response_wraps_non_dict_payloads(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            future = loop.create_future()
            session = AgentRelaySession(
                websocket=None,
                connector_id="windows-01",
                instance_id="instance-01",
                context_epoch=1,
                connection_generation="generation-01",
                capabilities=("connector_health", "files_list"),
                capability_profile="read_only",
                pending={"req-1": future},
            )

            AgentRelayEndpoint._receive_response(
                session,
                {
                    "v": 1,
                    "type": "response",
                    "request_id": "req-1",
                    "tool": "files.list",
                    "connector_id": "windows-01",
                    "status": "ok",
                    "result": ["a.txt", "b.txt"],
                },
            )

            self.assertTrue(future.done())
            self.assertEqual(
                future.result(),
                {"code": "ok", "result": ["a.txt", "b.txt"]},
            )
        finally:
            asyncio.set_event_loop(None)
            loop.close()

    def test_published_argument_schema_required_fields(self):
        """Lock the tool schema that clients actually receive from tools/list.

        The Hub catalog only carries scopes, so this connector signature is the
        single source of truth for which arguments are required. A required
        ``root`` on the command tools made callers fail validation before the
        device ever saw the request.
        """
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = RemoteAgentConfig(
                database_url=f"sqlite:///{Path(temp_dir.name) / 'remote-agent.sqlite'}",
                mcp_bearer_token="m" * 48,
                hub_delegation_secret="d" * 48,
                operator_bearer_token="o" * 48,
                hub_audience="remote-agent-connector",
                private_mcp_url="http://127.0.0.1:3030/mcp",
                bind_host="127.0.0.1",
                bind_port=3030,
                allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
                allow_insecure_private_mcp=True,
                trust_proxy_tls=False,
                request_timeout_seconds=2,
                heartbeat_timeout_seconds=2,
            )
            store = RemoteAgentStore(config.database_url)
            app = create_app(config, store)
            tools = {
                tool.name: tool.inputSchema
                for tool in asyncio.run(app.state.mcp_server.list_tools())
            }

            for name in ("terminal_execute", "ssh_execute"):
                with self.subTest(tool=name):
                    required = tools[name].get("required") or []
                    self.assertNotIn("root", required)
                    self.assertIn("command", required)
                    self.assertIn("profile_id", required)
                    self.assertIn("idempotency_key", required)
                    root = tools[name]["properties"]["root"]
                    self.assertIsNone(root.get("default"))

            # File tools stay root-scoped.
            for name in ("files_read", "files_list", "files_write"):
                with self.subTest(tool=name):
                    required = tools[name].get("required") or []
                    self.assertIn("root", required)
                    self.assertIn("path", required)

            self.assertIn("host", tools["ssh_execute"].get("required") or [])
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()
