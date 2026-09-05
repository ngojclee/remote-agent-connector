"""Capability ceiling and catalog agreement for the Remote Agent connector.

Three separate lists used to describe what a device can do: the Hub tool
catalog, this connector's capability profiles, and the tools the connector
actually publishes. They disagreed, which made an unimplemented tool look like
a permissions failure. These tests pin them together and prove the enrolled
profile is enforced when a call is dispatched, not only at authentication.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.errors import AgentError
from remote_agent_connector.protocol import (
    FULL_AGENT_CAPABILITIES,
    READ_ONLY_CAPABILITIES,
    READ_WRITE_CAPABILITIES,
    DelegatedIdentity,
    capabilities_for_profile,
)
from remote_agent_connector.relay import AgentRelaySession
from remote_agent_connector.server import create_app
from remote_agent_connector.service import RemoteAgentService
from remote_agent_connector.store import RemoteAgentStore


class _AnsweringWebSocket:
    """Answers a relay request the way a healthy device would."""

    def __init__(self):
        self.sent: list[dict] = []

    async def send_json(self, message: dict) -> None:
        self.sent.append(message)
        session = self._session
        future = session.pending.get(message["request_id"])
        if future is not None and not future.done():
            future.set_result({"code": "ok"})


class _StubRegistry:
    def __init__(self, session):
        self._session = session

    async def get_exact(self, *, connector_id: str, instance_id: str):
        if self._session is None:
            return None
        if (
            self._session.connector_id == connector_id
            and self._session.instance_id == instance_id
        ):
            return self._session
        return None


class CapabilityContractTests(unittest.TestCase):
    def _config(self, temp_dir: str) -> RemoteAgentConfig:
        return RemoteAgentConfig(
            database_url=f"sqlite:///{Path(temp_dir) / 'contract.sqlite'}",
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
            request_timeout_seconds=5,
            heartbeat_timeout_seconds=30,
        )

    def test_profiles_are_nested_and_exclude_unimplemented_tools(self):
        read_only = set(READ_ONLY_CAPABILITIES)
        read_write = set(READ_WRITE_CAPABILITIES)
        full = set(FULL_AGENT_CAPABILITIES)
        self.assertTrue(read_only <= read_write <= full)
        self.assertNotIn("terminal_stream", full)
        self.assertIn("skills_materialize", read_only)
        self.assertEqual(len(full), len(capabilities_for_profile("full_agent")))

    def test_published_tools_match_full_agent_profile(self):
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = self._config(temp_dir.name)
            store = RemoteAgentStore(config.database_url)
            app = create_app(config, store)
            published = {
                tool.name
                for tool in asyncio.run(app.state.mcp_server.list_tools())
            }
            self.assertEqual(published, set(FULL_AGENT_CAPABILITIES))
            self.assertNotIn("terminal_stream", published)
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()

    def test_reported_capabilities_follow_the_profile_not_the_frozen_column(self):
        """Inventory must agree with what the connector actually enforces.

        Capabilities were written once at enrollment, so a connector release
        that changed a profile kept reporting the old list while enforcing the
        new one. Both now derive from the enrolled profile.
        """
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = self._config(temp_dir.name)
            store = RemoteAgentStore(config.database_url)
            now = datetime.now(timezone.utc)
            self.assertTrue(
                store.enroll_device(
                    connector_id="agy2api-10.11.1.1",
                    public_key="k" * 43,
                    display_label="Verify",
                    capability_profile="full_agent",
                    platform="Windows 11",
                    now=now,
                )
            )
            # Simulate a row enrolled under an older profile definition.
            store._execute(
                "UPDATE remote_agent_devices SET capabilities_json = ?"
                " WHERE connector_id = ?",
                (
                    json.dumps(
                        ["connector_health", "terminal_stream"],
                        separators=(",", ":"),
                    ),
                    "agy2api-10.11.1.1",
                ),
            )
            service = RemoteAgentService(config=config, store=store)
            status = service.device_status(
                connector_id="agy2api-10.11.1.1"
            )
            self.assertNotIn("terminal_stream", status["capabilities"])
            self.assertIn("skills_materialize", status["capabilities"])
            self.assertEqual(
                sorted(status["capabilities"]),
                sorted(FULL_AGENT_CAPABILITIES),
            )
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()

    def _run_dispatch(self, *, capability_profile: str, tool: str) -> dict:
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = self._config(temp_dir.name)
            store = RemoteAgentStore(config.database_url)
            service = RemoteAgentService(config=config, store=store)
            now = datetime.now(timezone.utc)
            self.assertTrue(
                store.enroll_device(
                    connector_id="agy2api-10.11.1.1",
                    public_key="k" * 43,
                    display_label="Verify",
                    capability_profile=capability_profile,
                    platform="Windows 11",
                    now=now,
                )
            )
            self.assertTrue(
                store.upsert_presence(
                    connector_id="agy2api-10.11.1.1",
                    instance_id="instance-01",
                    connection_generation="generation-01",
                    context_epoch=1,
                    capabilities=tuple(
                        capabilities_for_profile(capability_profile)
                    ),
                    now=now,
                )
            )
            websocket = _AnsweringWebSocket()
            session = AgentRelaySession(
                websocket=websocket,
                connector_id="agy2api-10.11.1.1",
                instance_id="instance-01",
                context_epoch=1,
                connection_generation="generation-01",
                capabilities=tuple(
                    capabilities_for_profile(capability_profile)
                ),
                capability_profile=capability_profile,
            )
            websocket._session = session
            service.set_registry(_StubRegistry(session))
            identity = DelegatedIdentity(
                client_id="agy2api",
                scopes=("agent:read", "agent:write"),
                nonce="n" * 24,
                timestamp=0,
            )

            async def call():
                return await service.device_command(
                    identity=identity,
                    tool=tool,
                    connector_id="agy2api-10.11.1.1",
                    arguments={"root": "workspace", "path": "."},
                    idempotency_key=f"verify-{tool}-{capability_profile}",
                )

            return asyncio.run(call())
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()

    def test_allowed_call_reaches_the_device(self):
        result = self._run_dispatch(
            capability_profile="read_only",
            tool="files.read",
        )
        self.assertEqual(result["code"], "ok")

    def test_denied_call_is_blocked_before_the_device(self):
        """A read_only device must not be dispatched a write verb."""
        with self.assertRaises(AgentError) as raised:
            self._run_dispatch(
                capability_profile="read_only",
                tool="files.write",
            )
        self.assertEqual(raised.exception.code, "capability_not_granted")

    def test_denied_call_blocks_unimplemented_terminal_stream(self):
        with self.assertRaises(AgentError) as raised:
            self._run_dispatch(
                capability_profile="full_agent",
                tool="terminal.stream",
            )
        self.assertEqual(raised.exception.code, "capability_not_granted")

    def test_full_agent_profile_allows_terminal_and_ssh(self):
        for tool in ("terminal.execute", "ssh.execute", "skills.materialize"):
            with self.subTest(tool=tool):
                result = self._run_dispatch(
                    capability_profile="full_agent",
                    tool=tool,
                )
                self.assertEqual(result["code"], "ok")

    def test_stale_column_device_still_enforces_current_profile(self):
        """A device enrolled under an older profile is not grandfathered in."""
        temp_dir = tempfile.TemporaryDirectory()
        store = None
        try:
            config = self._config(temp_dir.name)
            store = RemoteAgentStore(config.database_url)
            now = datetime.now(timezone.utc)
            store.enroll_device(
                connector_id="agy2api-10.11.1.1",
                public_key="k" * 43,
                display_label="Verify",
                capability_profile="read_only",
                platform="Windows 11",
                now=now,
            )
            # A device claiming a capability outside its profile is refused.
            self.assertFalse(
                store.upsert_presence(
                    connector_id="agy2api-10.11.1.1",
                    instance_id="instance-02",
                    connection_generation="generation-02",
                    context_epoch=1,
                    capabilities=("files_write",),
                    now=now,
                )
            )
            self.assertTrue(
                store.upsert_presence(
                    connector_id="agy2api-10.11.1.1",
                    instance_id="instance-02",
                    connection_generation="generation-02",
                    context_epoch=1,
                    capabilities=("files_read",),
                    now=now,
                )
            )
        finally:
            if store is not None:
                store.close()
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
