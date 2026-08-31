from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fleet_connector.config import FleetConfig
from fleet_connector.db import Database
from fleet_connector.protocol import (
    DelegatedIdentity,
    LIFECYCLE_CAPABILITIES,
    LIFECYCLE_PROTOCOL_VERSION,
    b64url_encode,
    enrollment_payload,
    relay_auth_payload,
    relay_auth_payload_v2,
    relay_permission_posture,
)
from fleet_connector.service import FleetService
from fleet_connector.store import FleetStore


AGENT_A = "agent-a"
AGENT_B = "agent-b"
WORKSPACE_A = "11111111-1111-4111-8111-111111111111"
WORKSPACE_B = "22222222-2222-4222-8222-222222222222"


@dataclass
class FixedClock:
    value: datetime

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class ServiceFixture:
    def __init__(self, *, browser_control_enabled: bool = False):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.clock = FixedClock(
            datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
        )
        self.config = FleetConfig(
            database_url=(
                "sqlite:///"
                + str(Path(self.temp_dir.name, "fleet.sqlite"))
            ),
            mcp_bearer_token="m" * 48,
            hub_delegation_secret="d" * 48,
            operator_bearer_token="o" * 48,
            hub_audience="veilbrowser-fleet-connector",
            private_mcp_url="http://127.0.0.1:3020/mcp",
            public_relay_url="ws://127.0.0.1:3020/relay",
            bind_host="127.0.0.1",
            bind_port=3020,
            allowed_hosts=(
                "127.0.0.1:3020",
                "localhost:3020",
            ),
            allow_insecure_dev_relay=True,
            allow_insecure_private_mcp=True,
            trust_proxy_tls=False,
            lifecycle_enabled=True,
            browser_control_enabled=browser_control_enabled,
            relay_request_timeout_seconds=2,
        )
        self.database = Database(self.config.database_url)
        self.store = FleetStore(self.database)
        self.store.migrate()
        self.service = FleetService(
            config=self.config,
            store=self.store,
            now=self.clock.now,
        )

    def close(self) -> None:
        self.database.close()
        self.temp_dir.cleanup()

    def identity(
        self,
        agent: str = AGENT_A,
        scopes: tuple[str, ...] = ("fleet:read",),
    ) -> DelegatedIdentity:
        return DelegatedIdentity(
            client_id=agent,
            scopes=scopes,
            nonce="n" * 24,
            timestamp=int(self.clock.now().timestamp()),
        )


def create_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_key, b64url_encode(public_key)


def enroll_device(
    fixture: ServiceFixture,
    *,
    agent_principal: str = AGENT_A,
    workspace_id: str = WORKSPACE_A,
    device_id: str | None = None,
    display_label: str = "Test desktop",
) -> tuple[str, Ed25519PrivateKey, str]:
    device_id = device_id or str(uuid.uuid4())
    private_key, public_key = create_keypair()
    token = fixture.service.issue_enrollment_token(
        agent_principal=agent_principal,
        workspace_id=workspace_id,
        display_label=display_label,
        expires_in_seconds=120,
    )
    challenge = fixture.service.issue_relay_challenge(
        purpose="authenticate"
    )
    signature = b64url_encode(
        private_key.sign(
            enrollment_payload(
                challenge_id=str(challenge["challenge_id"]),
                challenge=str(challenge["challenge"]),
                device_id=device_id,
                enrollment_token=token,
                public_key=public_key,
            )
        )
    )
    fixture.service.complete_enrollment(
        challenge_id=str(challenge["challenge_id"]),
        challenge=str(challenge["challenge"]),
        device_id=device_id,
        enrollment_token=token,
        public_key=public_key,
        signature=signature,
    )
    return device_id, private_key, public_key


def authenticate_instance(
    fixture: ServiceFixture,
    *,
    device_id: str,
    private_key: Ed25519PrivateKey,
    workspace_id: str = WORKSPACE_A,
    instance_id: str | None = None,
    context_epoch: int = 1,
) -> str:
    instance_id = instance_id or str(uuid.uuid4())
    challenge = fixture.service.issue_relay_challenge(
        purpose="authenticate"
    )
    signature = b64url_encode(
        private_key.sign(
            relay_auth_payload(
                challenge_id=str(challenge["challenge_id"]),
                challenge=str(challenge["challenge"]),
                device_id=device_id,
                instance_id=instance_id,
                context_epoch=context_epoch,
                workspace_id=workspace_id,
            )
        )
    )
    fixture.service.authenticate_relay(
        challenge_id=str(challenge["challenge_id"]),
        challenge=str(challenge["challenge"]),
        device_id=device_id,
        instance_id=instance_id,
        context_epoch=context_epoch,
        workspace_id=workspace_id,
        signature=signature,
    )
    return instance_id


def authenticate_lifecycle_instance(
    fixture: ServiceFixture,
    *,
    device_id: str,
    private_key: Ed25519PrivateKey,
    workspace_id: str = WORKSPACE_A,
    instance_id: str | None = None,
    context_epoch: int = 1,
    capabilities: tuple[str, ...] = LIFECYCLE_CAPABILITIES,
) -> str:
    instance_id = instance_id or str(uuid.uuid4())
    permission_posture = relay_permission_posture(capabilities)
    challenge = fixture.service.issue_relay_challenge(
        purpose="authenticate"
    )
    signature = b64url_encode(
        private_key.sign(
            relay_auth_payload_v2(
                challenge_id=str(challenge["challenge_id"]),
                challenge=str(challenge["challenge"]),
                device_id=device_id,
                instance_id=instance_id,
                context_epoch=context_epoch,
                workspace_id=workspace_id,
                permission_posture=permission_posture,
                capabilities=list(capabilities),
            )
        )
    )
    fixture.service.authenticate_relay(
        challenge_id=str(challenge["challenge_id"]),
        challenge=str(challenge["challenge"]),
        device_id=device_id,
        instance_id=instance_id,
        context_epoch=context_epoch,
        workspace_id=workspace_id,
        signature=signature,
        protocol_version=LIFECYCLE_PROTOCOL_VERSION,
        capabilities=capabilities,
        permission_posture=permission_posture,
    )
    return instance_id
