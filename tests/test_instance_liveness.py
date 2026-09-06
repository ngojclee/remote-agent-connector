"""Device liveness is derived from heartbeat freshness, not a stored flag.

A row left behind by a crash used to stay `online` forever, so both the reported
inventory and routing could name a device that no longer existed. These tests
pin the three properties that matter: a brief blip must not retire a healthy
device, a dead device must be reported offline and have its row closed, and the
reported online count must equal the number of real live devices.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.protocol import (
    HEARTBEAT_INTERVAL_SECONDS,
    INSTANCE_STALE_MULTIPLIER,
    capabilities_for_profile,
    instance_stale_seconds,
)
from remote_agent_connector.service import RemoteAgentService
from remote_agent_connector.store import RemoteAgentStore, as_timestamp


class _NeverRegistry:
    async def get_exact(self, *, connector_id: str, instance_id: str):
        return None


class StaleWindowTests(unittest.TestCase):
    def test_window_is_five_heartbeat_intervals(self):
        self.assertEqual(INSTANCE_STALE_MULTIPLIER, 5)
        self.assertEqual(
            instance_stale_seconds(30),
            HEARTBEAT_INTERVAL_SECONDS * INSTANCE_STALE_MULTIPLIER,
        )
        self.assertEqual(instance_stale_seconds(30), 75)

    def test_a_longer_configured_timeout_is_never_shrunk(self):
        self.assertEqual(instance_stale_seconds(120), 120)

    def test_config_derives_the_window_from_its_own_timeout(self):
        config = self._config(heartbeat_timeout=30)
        self.assertEqual(config.instance_stale_seconds, 75)
        wide = self._config(heartbeat_timeout=200)
        self.assertEqual(wide.instance_stale_seconds, 200)

    def _config(self, *, heartbeat_timeout: int) -> RemoteAgentConfig:
        return RemoteAgentConfig(
            database_url="sqlite:///:memory:",
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
            heartbeat_timeout_seconds=heartbeat_timeout,
        )


class InstanceLivenessTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = None

    def tearDown(self):
        if self.store is not None:
            self.store.close()
        self.temp_dir.cleanup()

    def _service(self, *, now: datetime) -> RemoteAgentService:
        config = RemoteAgentConfig(
            database_url=f"sqlite:///{Path(self.temp_dir.name) / 'live.sqlite'}",
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
        self.store = RemoteAgentStore(config.database_url)
        service = RemoteAgentService(
            config=config,
            store=self.store,
            clock=lambda: now,
        )
        service.set_registry(_NeverRegistry())
        return service

    def _enroll(self, connector_id: str) -> None:
        self.store.enroll_device(
            connector_id=connector_id,
            public_key="k" * 43,
            display_label=connector_id,
            capability_profile="full_agent",
            platform="Windows 11",
            now=datetime(2026, 9, 1, tzinfo=timezone.utc),
        )

    def _presence(
        self,
        connector_id: str,
        *,
        instance_id: str,
        generation: str,
        heartbeat_at: datetime,
    ) -> None:
        self.store.upsert_presence(
            connector_id=connector_id,
            instance_id=instance_id,
            connection_generation=generation,
            context_epoch=1,
            capabilities=tuple(capabilities_for_profile("full_agent")),
            now=heartbeat_at,
        )

    def test_a_short_blip_keeps_the_device_online(self):
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
        service = self._service(now=now)
        self._enroll("dev-blip")
        # Four missed beats is inside the five-beat window.
        self._presence(
            "dev-blip",
            instance_id="i-blip",
            generation="g-blip",
            heartbeat_at=now - timedelta(seconds=60),
        )
        status = service.device_status(connector_id="dev-blip")
        self.assertEqual(status["connection_state"], "online")
        self.assertEqual(service.online_agents()["count"], 1)
        row = self.store.latest_online_instance(
            connector_id="dev-blip", fresh_after=service._fresh_after()
        )
        self.assertIsNotNone(row)
        self.assertEqual(row["instance_id"], "i-blip")

    def test_a_dead_device_is_reported_offline_and_its_row_closed(self):
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
        silence = now - timedelta(seconds=200)
        service = self._service(now=now)
        self._enroll("dev-dead")
        self._presence(
            "dev-dead",
            instance_id="i-dead",
            generation="g-dead",
            heartbeat_at=silence,
        )
        status = service.device_status(connector_id="dev-dead")
        self.assertEqual(status["connection_state"], "offline")
        self.assertIsNone(status["last_heartbeat_at"])
        self.assertEqual(service.online_agents()["count"], 0)
        stored = self.store._fetchone(
            "select state, disconnected_at from live_instances where instance_id = ?",
            ("i-dead",),
        )
        self.assertEqual(stored["state"], "offline")
        # The reaper records the last evidence of life rather than the sweep
        # time, so a reaped row never claims the device outlived its silence.
        self.assertEqual(
            stored["disconnected_at"], as_timestamp(silence)
        )

    def test_online_count_equals_the_number_of_live_devices(self):
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
        service = self._service(now=now)
        for connector_id, alive in (
            ("dev-live", True),
            ("dev-dead-a", False),
            ("dev-dead-b", False),
        ):
            self._enroll(connector_id)
            self._presence(
                connector_id,
                instance_id=f"i-{connector_id}",
                generation=f"g-{connector_id}",
                heartbeat_at=(
                    now - timedelta(seconds=10)
                    if alive
                    else now - timedelta(seconds=300)
                ),
            )
        self.assertEqual(service.online_agents()["count"], 1)
        devices = service.operator_devices()["devices"]
        self.assertEqual(len(devices), 3)
        self.assertEqual(
            sorted(d["connector_id"] for d in devices if d["connection_state"] == "online"),
            ["dev-live"],
        )

    def test_a_crash_left_behind_row_is_never_reported_online(self):
        """The production shape: state stored online, heartbeat ancient."""
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
        service = self._service(now=now)
        self._enroll("dev-crash")
        stale = datetime(2026, 9, 2, 16, 43, 36, tzinfo=timezone.utc)
        self._presence(
            "dev-crash",
            instance_id="i-crash",
            generation="g-crash",
            heartbeat_at=stale,
        )
        # Nothing ever closed it, so the stored flag still says online.
        stored = self.store._fetchone(
            "select state from live_instances where instance_id = ?",
            ("i-crash",),
        )
        self.assertEqual(stored["state"], "online")
        self.assertEqual(
            service.device_status(connector_id="dev-crash")["connection_state"],
            "offline",
        )
        self.assertEqual(service.online_agents()["count"], 0)
        closed = self.store._fetchone(
            "select state, disconnected_at from live_instances where instance_id = ?",
            ("i-crash",),
        )
        self.assertEqual(closed["state"], "offline")
        self.assertIsNotNone(closed["disconnected_at"])

    def test_routing_still_prefers_the_freshest_heartbeat(self):
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
        service = self._service(now=now)
        self._enroll("dev-multi")
        self._presence(
            "dev-multi",
            instance_id="i-old",
            generation="g-old",
            heartbeat_at=now - timedelta(seconds=50),
        )
        self._presence(
            "dev-multi",
            instance_id="i-new",
            generation="g-new",
            heartbeat_at=now - timedelta(seconds=5),
        )
        row = self.store.latest_online_instance(
            connector_id="dev-multi", fresh_after=service._fresh_after()
        )
        self.assertEqual(row["instance_id"], "i-new")


if __name__ == "__main__":
    unittest.main()
