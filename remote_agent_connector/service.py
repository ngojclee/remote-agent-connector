from __future__ import annotations

import asyncio
import json
import uuid
from datetime import timedelta
from typing import Any

from .config import RemoteAgentConfig
from .errors import AgentError
from .protocol import (
    RESULT_MAX_BYTES,
    DelegatedIdentity,
    ProtocolError,
    capabilities_for_profile,
    canonical_json_digest,
    public_key_fingerprint,
)
from .store import RemoteAgentStore, as_timestamp, utc_now
class RemoteAgentService:
    def __init__(
        self,
        *,
        config: RemoteAgentConfig,
        store: RemoteAgentStore,
        clock=None,
    ):
        self.config = config
        self.store = store
        self.clock = clock or utc_now
        self.registry = None

    def set_registry(self, registry) -> None:
        self.registry = registry

    def issue_enrollment_token(
        self,
        *,
        connector_id: str,
        capability_profile: str,
        display_label: str,
        expires_in_seconds: int = 600,
    ) -> dict[str, Any]:
        try:
            token = self.store.issue_enrollment_token(
                connector_id=connector_id,
                capability_profile=capability_profile,
                display_label=display_label,
                expires_in_seconds=expires_in_seconds,
                now=self.clock(),
            )
            self.store.append_audit(
                action="operator.enrollment_token_issued",
                result_code="ok",
                connector_id=connector_id,
                details={
                    "capability_profile": capability_profile,
                    "expires_in_seconds": expires_in_seconds,
                },
                now=self.clock(),
            )
            return {
                "enrollment_token": token,
                "expires_in_seconds": expires_in_seconds,
            }
        except Exception:
            raise AgentError("invalid_enrollment_request")

    def complete_enrollment(
        self,
        *,
        challenge_id: str,
        challenge: str,
        connector_id: str,
        enrollment_token: str,
        public_key: str,
        signature: str,
        platform: str = "unknown",
    ) -> dict[str, Any]:
        from .protocol import (
            enrollment_payload,
            parse_connector_id,
            parse_public_key,
            validate_platform,
            verify_ed25519,
        )

        now = self.clock()
        platform = validate_platform(platform)
        token_record = self.store.consume_enrollment_token(
            raw_token=enrollment_token,
            connector_id=connector_id,
            now=now,
        )
        if token_record is None:
            raise AgentError("invalid_enrollment_token")
        if not self.store.consume_challenge(
            challenge_id=challenge_id,
            challenge=challenge,
            now=now,
        ):
            raise AgentError("invalid_challenge")
        payload = enrollment_payload(
            challenge_id=challenge_id,
            challenge=challenge,
            connector_id=connector_id,
            enrollment_token=enrollment_token,
            public_key=public_key,
        )
        try:
            verify_ed25519(
                public_key_b64=public_key,
                payload=payload,
                signature_b64=signature,
            )
        except ProtocolError:
            raise AgentError("invalid_signature") from None
        enrolled = self.store.enroll_device(
            connector_id=connector_id,
            public_key=public_key,
            display_label=token_record["display_label"],
            capability_profile=token_record["capability_profile"],
            now=now,
            platform=platform,
        )
        if not enrolled:
            raise AgentError("device_already_enrolled")
        self.store.append_audit(
            action="device.enrolled",
            result_code="ok",
            connector_id=connector_id,
            details={
                "capability_profile": token_record["capability_profile"],
                "public_key_fingerprint": public_key_fingerprint(public_key),
            },
            now=now,
        )
        return {
            "connector_id": connector_id,
            "capability_profile": token_record["capability_profile"],
            "capabilities": list(
                capabilities_for_profile(token_record["capability_profile"])
            ),
        }

    def issue_relay_challenge(self) -> dict[str, Any]:
        challenge = self.store.create_challenge(now=self.clock())
        return {
            "v": 1,
            "type": "challenge",
            **challenge,
        }

    def authenticate_relay(
        self,
        *,
        challenge_id: str,
        challenge: str,
        connector_id: str,
        instance_id: str,
        context_epoch: int,
        signature: str,
        connection_generation: str,
        capabilities: tuple[str, ...],
    ) -> dict[str, Any]:
        from .protocol import (
            parse_connector_id,
            parse_instance_id,
            relay_auth_payload,
            verify_ed25519,
        )

        now = self.clock()
        if not self.store.consume_challenge(
            challenge_id=challenge_id,
            challenge=challenge,
            now=now,
        ):
            raise AgentError("invalid_challenge")
        device = self.store.get_device(connector_id)
        if device is None or device["enrollment_state"] != "enrolled":
            raise AgentError("device_revoked")
        payload = relay_auth_payload(
            challenge_id=challenge_id,
            challenge=challenge,
            connector_id=connector_id,
            instance_id=instance_id,
            context_epoch=context_epoch,
        )
        try:
            verify_ed25519(
                public_key_b64=device["public_key"],
                payload=payload,
                signature_b64=signature,
            )
        except ProtocolError:
            raise AgentError("invalid_signature") from None
        accepted = self.store.upsert_presence(
            connector_id=connector_id,
            instance_id=instance_id,
            connection_generation=connection_generation,
            context_epoch=context_epoch,
            capabilities=capabilities,
            now=now,
        )
        if not accepted:
            raise AgentError("capabilities_not_granted")
        self.store.append_audit(
            action="device.online",
            result_code="ok",
            connector_id=connector_id,
            details={"instance_id": instance_id},
            now=now,
        )
        return {
            "connector_id": connector_id,
            "instance_id": instance_id,
            "context_epoch": context_epoch,
            "connection_generation": connection_generation,
            "capabilities": capabilities,
        }

    def heartbeat(
        self,
        *,
        instance_id: str,
        connection_generation: str,
        context_epoch: int,
        capabilities: tuple[str, ...],
    ) -> None:
        from .protocol import parse_instance_id

        instance_id = parse_instance_id(instance_id)
        accepted = self.store.heartbeat(
            instance_id=instance_id,
            connection_generation=connection_generation,
            context_epoch=context_epoch,
            now=self.clock(),
        )
        if not accepted:
            raise AgentError("stale_connection")

    def disconnect_relay(
        self,
        *,
        instance_id: str,
        connection_generation: str,
    ) -> None:
        from .protocol import parse_instance_id

        self.store.disconnect_instance(
            instance_id=parse_instance_id(instance_id),
            connection_generation=connection_generation,
            now=self.clock(),
        )

    def device_status(self, *, connector_id: str) -> dict[str, Any]:
        device = self.store.get_device(connector_id)
        if device is None:
            raise AgentError("device_not_found")
        instance = self.store.latest_online_instance(connector_id=connector_id)
        capabilities = list(
            capabilities_for_profile(device["capability_profile"])
        )
        return {
            "connector_id": connector_id,
            "display_label": device["display_label"],
            "public_key_fingerprint": public_key_fingerprint(
                device["public_key"]
            ),
            "capability_profile": device["capability_profile"],
            "capabilities": capabilities,
            "enrollment_state": device["enrollment_state"],
            "enrolled_at": device["enrolled_at"],
            "revoked_at": device["revoked_at"],
            "connection_state": (
                "online" if instance else "offline"
            ),
            "last_heartbeat_at": instance["last_heartbeat_at"] if instance else None,
            "context_epoch": instance["context_epoch"] if instance else None,
        }

    def operator_devices(self) -> dict[str, Any]:
        devices = []
        for device in self.store.list_devices():
            status = self.device_status(connector_id=device["connector_id"])
            devices.append(status)
        return {"devices": devices, "count": len(devices)}

    def online_agents(self) -> dict[str, Any]:
        rows = self.store.online_agents(
            stale_before=self.clock()
            - timedelta(seconds=self.config.heartbeat_timeout_seconds)
        )
        agents = []
        for row in rows:
            capabilities = list(
                capabilities_for_profile(row["capability_profile"])
            )
            agents.append(
                {
                    "device_id": row["device_id"],
                    "platform": row["platform"] or "unknown",
                    "capabilities": (
                        capabilities if isinstance(capabilities, list) else []
                    ),
                    "health": "online",
                    "connected_at": row["connected_at"],
                }
            )
        return {"agents": agents, "count": len(agents)}

    def revoke_device(self, *, connector_id: str) -> dict[str, Any]:
        if not self.store.revoke_device(connector_id=connector_id, now=self.clock()):
            raise AgentError("device_not_found")
        self.store.append_audit(
            action="device.revoked",
            result_code="ok",
            connector_id=connector_id,
            now=self.clock(),
        )
        return {"status": "revoked", "connector_id": connector_id}

    def delete_revoked_device(
        self,
        *,
        connector_id: str,
    ) -> dict[str, Any]:
        result = self.store.delete_revoked_device(connector_id=connector_id)
        if result != "deleted":
            raise AgentError(result)
        self.store.append_audit(
            action="device.deleted",
            result_code="ok",
            connector_id=connector_id,
            now=self.clock(),
        )
        return {"status": "deleted", "connector_id": connector_id}

    def rename_device(
        self,
        *,
        connector_id: str,
        display_label: str,
    ) -> dict[str, Any]:
        from .protocol import validate_display_label

        display_label = validate_display_label(display_label)
        device = self.store.get_device(connector_id)
        if device is None:
            raise AgentError("device_not_found")
        if device["enrollment_state"] != "enrolled":
            raise AgentError("device_revoked")
        self.store._execute(
            """
            UPDATE remote_agent_devices
            SET display_label = ?, updated_at = ?
            WHERE connector_id = ?
            """,
            (
                display_label,
                as_timestamp(self.clock()),
                connector_id,
            ),
        )
        self.store.append_audit(
            action="device.renamed",
            result_code="ok",
            connector_id=connector_id,
            now=self.clock(),
        )
        return {"connector_id": connector_id, "display_label": display_label}

    def _relay_session(
        self,
        *,
        connector_id: str,
        instance_id: str | None,
    ):
        from .protocol import parse_instance_id

        if instance_id:
            instance_id = parse_instance_id(instance_id)
            return self.store.exact_online_instance(
                connector_id=connector_id,
                instance_id=instance_id,
            )
        return self.store.latest_online_instance(connector_id=connector_id)

    async def device_command(
        self,
        *,
        identity: DelegatedIdentity,
        tool: str,
        connector_id: str,
        arguments: dict[str, Any],
        idempotency_key: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        from .protocol import parse_connector_id

        connector_id = parse_connector_id(connector_id)
        session_row = self._relay_session(
            connector_id=connector_id,
            instance_id=instance_id,
        )
        if session_row is None:
            raise AgentError("device_offline")
        if self.registry is None:
            raise AgentError("relay_unavailable")
        session = await self.registry.get_exact(
            connector_id=connector_id,
            instance_id=session_row["instance_id"],
        )
        if session is None:
            raise AgentError("device_offline")
        # Enforce the enrolled capability ceiling at execution time, not only
        # at authentication. Relay verbs are dotted (`files.list`) while
        # capabilities are underscore (`files_list`), so normalise before the
        # lookup. Without this the Hub catalog and client scopes were the only
        # gates and a read_only device could be dispatched a write verb.
        capability = tool.replace(".", "_")
        if not session.has_capability(capability):
            raise AgentError("capability_not_granted")
        request_id = str(uuid.uuid4())
        request_digest = canonical_json_digest(
            {
                "connector_id": connector_id,
                "tool": tool,
                "arguments": arguments,
                "instance_id": session_row["instance_id"],
                "context_epoch": session_row["context_epoch"],
            }
        )
        outcome, replay = self.store.claim_request(
            connector_id=connector_id,
            idempotency_key=idempotency_key,
            request_id=request_id,
            tool_name=tool,
            request_digest=request_digest,
            now=self.clock(),
        )
        if outcome == "conflict":
            raise AgentError("idempotency_conflict")
        if outcome == "replay":
            return replay
        if outcome == "pending":
            raise AgentError("request_pending")
        future: asyncio.Future[dict[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        session.pending[request_id] = future
        try:
            await session.websocket.send_json(
                {
                    "v": 1,
                    "type": "request",
                    "request_id": request_id,
                    "tool": tool,
                    "connector_id": connector_id,
                    "arguments": arguments,
                    # Carry the already-verified application identity to the
                    # device. The connector holds the delegation secret and has
                    # checked the signature, so the device gets the binding
                    # without ever receiving the secret itself. Omitted entirely
                    # for legacy v3 callers so their frames are byte-identical.
                    **(
                        {
                            "app_id": identity.app_id,
                            "app_assertion": {
                                "source": "hub-delegation-v4",
                                "verified": True,
                                "client_id": identity.client_id,
                            },
                        }
                        if identity.app_id
                        else {}
                    ),
                }
            )
            result = await asyncio.wait_for(
                future,
                timeout=self.config.request_timeout_seconds,
            )
        except asyncio.TimeoutError:
            self.store.complete_request(
                connector_id=connector_id,
                idempotency_key=idempotency_key,
                status="failed",
                result={"code": "device_timeout"},
                now=self.clock(),
            )
            raise AgentError("device_timeout") from None
        except Exception:
            self.store.complete_request(
                connector_id=connector_id,
                idempotency_key=idempotency_key,
                status="failed",
                result={"code": "device_offline"},
                now=self.clock(),
            )
            raise AgentError("device_offline") from None
        finally:
            session.pending.pop(request_id, None)
        encoded = json.dumps(
            result,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        if len(encoded) > RESULT_MAX_BYTES:
            self.store.complete_request(
                connector_id=connector_id,
                idempotency_key=idempotency_key,
                status="failed",
                result={"code": "result_too_large"},
                now=self.clock(),
            )
            raise AgentError("result_too_large")
        self.store.complete_request(
            connector_id=connector_id,
            idempotency_key=idempotency_key,
            status="completed",
            result=result,
            now=self.clock(),
        )
        self.store.append_audit(
            action=f"mcp.{tool}",
            result_code=str(result.get("code") or "ok"),
            agent_principal=identity.client_id,
            connector_id=connector_id,
            request_id=request_id,
            now=self.clock(),
        )
        return result
