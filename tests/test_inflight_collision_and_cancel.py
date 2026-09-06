"""In-flight collision guard and the cancel verb.

A model-level retry used to run the same mutating command twice at once on a
real machine, because the only guard keyed on the caller's idempotency key and
callers rotate that key per call. These tests pin the guard to the request
content instead, and pin that read verbs and legitimate repeats are never
blocked. They also pin the cancel frame shape the Windows lane implements
against.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.errors import AgentError
from remote_agent_connector.protocol import (
    MUTATING_RELAY_TOOLS,
    RELAY_CANCEL_FIELDS,
    DelegatedIdentity,
    ProtocolError,
    build_cancel_frame,
    capabilities_for_profile,
)
from remote_agent_connector.relay import AgentRelaySession
from remote_agent_connector.service import RemoteAgentService
from remote_agent_connector.store import RemoteAgentStore

CONNECTOR = "agy2api-10.11.1.1"


class _HoldingWebSocket:
    """Records frames and answers only when the test says so."""

    def __init__(self):
        self.sent: list[dict] = []
        self._session: AgentRelaySession | None = None

    async def send_json(self, message: dict) -> None:
        self.sent.append(message)

    def answer(self, request_id: str, result: dict | None = None) -> None:
        future = self._session.pending.get(request_id)
        if future is not None and not future.done():
            future.set_result(result or {"code": "ok"})

    def request_ids(self) -> list[str]:
        return [m["request_id"] for m in self.sent if "request_id" in m]


class _StubRegistry:
    def __init__(self, session):
        self._session = session

    async def get_exact(self, *, connector_id: str, instance_id: str):
        if (
            self._session is not None
            and self._session.connector_id == connector_id
            and self._session.instance_id == instance_id
        ):
            return self._session
        return None


class _Harness:
    def __enter__(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = RemoteAgentConfig(
            database_url=f"sqlite:///{Path(self.temp_dir.name) / 'guard.sqlite'}",
            mcp_bearer_token="m" * 48,
            hub_delegation_secret="d" * 48,
            operator_bearer_token="o" * 48,
            hub_audience="remote-agent-connector",
            private_mcp_url="http://127.0.0.1:3030/mcp",
            bind_host="127.0.0.1",
            bind_port=3030,
            allowed_hosts=("127.0.0.1:3030",),
            allow_insecure_private_mcp=True,
            trust_proxy_tls=False,
            request_timeout_seconds=5,
            heartbeat_timeout_seconds=30,
        )
        self.store = RemoteAgentStore(self.config.database_url)
        self.service = RemoteAgentService(
            config=self.config, store=self.store
        )
        now = datetime.now(timezone.utc)
        self.store.enroll_device(
            connector_id=CONNECTOR,
            public_key="k" * 43,
            display_label="Guard",
            capability_profile="full_agent",
            platform="Windows 11",
            now=now,
        )
        self.store.upsert_presence(
            connector_id=CONNECTOR,
            instance_id="instance-01",
            connection_generation="generation-01",
            context_epoch=1,
            capabilities=tuple(capabilities_for_profile("full_agent")),
            now=now,
        )
        self.websocket = _HoldingWebSocket()
        self.session = AgentRelaySession(
            websocket=self.websocket,
            connector_id=CONNECTOR,
            instance_id="instance-01",
            context_epoch=1,
            connection_generation="generation-01",
            capabilities=tuple(capabilities_for_profile("full_agent")),
            capability_profile="full_agent",
        )
        self.websocket._session = self.session
        self.service.set_registry(_StubRegistry(self.session))
        return self

    def __exit__(self, *exc_info):
        self.store.close()
        self.temp_dir.cleanup()

    def identity(self) -> DelegatedIdentity:
        return DelegatedIdentity(
            client_id="agy2api",
            scopes=("agent:read", "agent:write", "agent:terminal"),
            nonce="n" * 24,
            timestamp=0,
        )

    def start(self, tool: str, arguments: dict, key: str):
        """Begin a device call without waiting for it to finish."""
        return asyncio.get_running_loop().create_task(
            self.service.device_command(
                identity=self.identity(),
                tool=tool,
                connector_id=CONNECTOR,
                arguments=arguments,
                idempotency_key=key,
            )
        )


class InFlightCollisionTests(unittest.TestCase):
    def test_identical_mutating_command_is_refused_busy(self):
        async def scenario():
            with _Harness() as h:
                first = h.start(
                    "terminal.execute",
                    {"command": "git commit -m x"},
                    "key-a",
                )
                await asyncio.sleep(0.05)
                with self.assertRaises(AgentError) as raised:
                    await h.service.device_command(
                        identity=h.identity(),
                        tool="terminal.execute",
                        connector_id=CONNECTOR,
                        arguments={"command": "git commit -m x"},
                        idempotency_key="key-b",
                    )
                self.assertEqual(
                    raised.exception.code, "command_in_flight"
                )
                h.websocket.answer(h.websocket.request_ids()[0])
                self.assertEqual((await first)["code"], "ok")
        asyncio.run(scenario())

    def test_same_command_runs_again_after_the_first_completes(self):
        async def scenario():
            with _Harness() as h:
                for key in ("key-a", "key-b"):
                    task = h.start(
                        "terminal.execute",
                        {"command": "git status"},
                        key,
                    )
                    await asyncio.sleep(0.05)
                    h.websocket.answer(h.websocket.request_ids()[-1])
                    result = await task
                    self.assertEqual(result["code"], "ok")
        asyncio.run(scenario())

    def test_git_status_before_and_after_an_edit_both_run(self):
        """The guard must not dedup by arguments across time."""
        async def scenario():
            with _Harness() as h:
                arguments = {"root": "workspace", "path": "x"}
                before = h.start("files.read", arguments, "k1")
                await asyncio.sleep(0.05)
                h.websocket.answer(h.websocket.request_ids()[0])
                self.assertEqual((await before)["code"], "ok")
                edit = h.start(
                    "terminal.execute",
                    {"command": "git commit -m x"},
                    "k2",
                )
                await asyncio.sleep(0.05)
                h.websocket.answer(h.websocket.request_ids()[1])
                self.assertEqual((await edit)["code"], "ok")
                after = h.start("files.read", arguments, "k3")
                await asyncio.sleep(0.05)
                h.websocket.answer(h.websocket.request_ids()[2])
                self.assertEqual((await after)["code"], "ok")
        asyncio.run(scenario())

    def test_read_only_tools_are_never_blocked(self):
        async def scenario():
            with _Harness() as h:
                arguments = {"root": "workspace", "path": "."}
                first = h.start("files.list", arguments, "k1")
                await asyncio.sleep(0.05)
                second = h.start("files.list", arguments, "k2")
                await asyncio.sleep(0.05)
                for request_id in h.websocket.request_ids():
                    h.websocket.answer(request_id)
                self.assertEqual((await first)["code"], "ok")
                self.assertEqual((await second)["code"], "ok")
                self.assertNotIn("files.list", MUTATING_RELAY_TOOLS)
        asyncio.run(scenario())

    def test_different_mutating_arguments_do_not_collide(self):
        async def scenario():
            with _Harness() as h:
                a = h.start("terminal.execute", {"command": "echo a"}, "k1")
                await asyncio.sleep(0.05)
                b = h.start("terminal.execute", {"command": "echo b"}, "k2")
                await asyncio.sleep(0.05)
                for request_id in h.websocket.request_ids():
                    h.websocket.answer(request_id)
                self.assertEqual((await a)["code"], "ok")
                self.assertEqual((await b)["code"], "ok")
        asyncio.run(scenario())

    def test_guard_is_released_when_the_relay_times_out(self):
        async def scenario():
            with _Harness() as h:
                task = h.start(
                    "terminal.execute", {"command": "sleep 99"}, "k1"
                )
                await asyncio.sleep(0.05)
                with self.assertRaises(AgentError):
                    await task
                retry = h.start(
                    "terminal.execute", {"command": "sleep 99"}, "k2"
                )
                await asyncio.sleep(0.05)
                h.websocket.answer(h.websocket.request_ids()[-1])
                self.assertEqual((await retry)["code"], "ok")
        asyncio.run(scenario())


class CancelVerbTests(unittest.TestCase):
    def test_cancel_frame_shape_is_exactly_the_published_contract(self):
        request_id = str(uuid.uuid4())
        frame = build_cancel_frame(
            connector_id=CONNECTOR, request_id=request_id
        )
        self.assertEqual(set(frame), set(RELAY_CANCEL_FIELDS))
        self.assertEqual(frame["type"], "cancel")
        self.assertEqual(frame["v"], 1)
        self.assertEqual(frame["request_id"], request_id)
        self.assertEqual(frame["connector_id"], CONNECTOR)
        self.assertNotIn("arguments", frame)
        self.assertNotIn("app_assertion", frame)

    def test_cancel_reaches_the_device_and_answers_the_waiter(self):
        async def scenario():
            with _Harness() as h:
                task = h.start(
                    "terminal.execute", {"command": "long build"}, "k1"
                )
                await asyncio.sleep(0.05)
                request_id = h.websocket.request_ids()[0]
                result = await h.service.cancel_request(
                    connector_id=CONNECTOR, request_id=request_id
                )
                self.assertEqual(result["code"], "ok")
                self.assertEqual(result["state"], "cancelled")
                cancel = h.websocket.sent[-1]
                self.assertEqual(cancel["type"], "cancel")
                self.assertEqual(cancel["request_id"], request_id)
                outcome = await task
                self.assertEqual(outcome["code"], "cancelled")
                again = h.start(
                    "terminal.execute", {"command": "long build"}, "k2"
                )
                await asyncio.sleep(0.05)
                h.websocket.answer(h.websocket.request_ids()[-1])
                self.assertEqual((await again)["code"], "ok")
        asyncio.run(scenario())

    def test_cancel_of_an_unknown_request_is_refused(self):
        async def scenario():
            with _Harness() as h:
                with self.assertRaises(AgentError) as raised:
                    await h.service.cancel_request(
                        connector_id=CONNECTOR,
                        request_id=str(uuid.uuid4()),
                    )
                self.assertEqual(
                    raised.exception.code, "request_not_in_flight"
                )
        asyncio.run(scenario())

    def test_cancel_requires_a_uuid_request_id(self):
        async def scenario():
            with _Harness() as h:
                with self.assertRaises(ProtocolError):
                    await h.service.cancel_request(
                        connector_id=CONNECTOR, request_id="not-a-uuid"
                    )
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
