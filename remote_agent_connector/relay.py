from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from starlette.websockets import WebSocket, WebSocketDisconnect

from .config import RemoteAgentConfig
from .errors import AgentError
from .protocol import (
    RELAY_MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    capabilities_for_profile,
)
from .service import RemoteAgentService


@dataclass
class AgentRelaySession:
    websocket: WebSocket
    connector_id: str
    instance_id: str
    context_epoch: int
    connection_generation: str
    capabilities: tuple[str, ...]
    capability_profile: str
    pending: dict[str, asyncio.Future[dict[str, Any]]] = field(
        default_factory=dict
    )

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def fail_pending(self) -> None:
        for future in self.pending.values():
            if not future.done():
                future.set_exception(AgentError("device_offline"))
        self.pending.clear()


class AgentRelayRegistry:
    def __init__(self):
        self._sessions: dict[str, AgentRelaySession] = {}
        self._lock = asyncio.Lock()

    async def register(self, session: AgentRelaySession) -> None:
        async with self._lock:
            existing = self._sessions.get(session.connector_id)
            if existing is not None:
                existing.fail_pending()
            self._sessions[session.connector_id] = session

    async def remove(self, session: AgentRelaySession) -> bool:
        removed = False
        async with self._lock:
            current = self._sessions.get(session.connector_id)
            if (
                current is session
                and current.connection_generation
                == session.connection_generation
            ):
                self._sessions.pop(session.connector_id, None)
                removed = True
        session.fail_pending()
        return removed

    async def get_exact(
        self,
        *,
        connector_id: str,
        instance_id: str,
    ) -> AgentRelaySession | None:
        async with self._lock:
            session = self._sessions.get(connector_id)
            if session is None or session.instance_id != instance_id:
                return None
            return session


class AgentRelayEndpoint:
    def __init__(
        self,
        *,
        config: RemoteAgentConfig,
        service: RemoteAgentService,
        registry: AgentRelayRegistry,
    ):
        self.config = config
        self.service = service
        self.registry = registry

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await self.handle(websocket)

    async def handle(self, websocket: WebSocket) -> None:
        if not self._is_secure_connection(websocket):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        session: AgentRelaySession | None = None
        registered = False
        connection_generation = str(uuid.uuid4())
        try:
            first_challenge = self.service.issue_relay_challenge()
            await websocket.send_json(first_challenge)
            message = await self._receive_message(websocket)
            if message.get("type") == "enroll":
                required = {
                    "v",
                    "type",
                    "challenge_id",
                    "challenge",
                    "connector_id",
                    "enrollment_token",
                    "public_key",
                    "signature",
                }
                self._require_keys(
                    message,
                    required,
                    allow_optional={"platform"},
                )
                if message["v"] != PROTOCOL_VERSION:
                    raise ProtocolError(
                        "relay protocol version is unsupported"
                    )
                enrollment_result = self.service.complete_enrollment(
                    challenge_id=message["challenge_id"],
                    challenge=message["challenge"],
                    connector_id=message["connector_id"],
                    enrollment_token=message["enrollment_token"],
                    public_key=message["public_key"],
                    signature=message["signature"],
                    platform=str(message.get("platform") or "unknown"),
                )
                await websocket.send_json(
                    {
                        "v": PROTOCOL_VERSION,
                        "type": "enrolled",
                        "connector_id": enrollment_result["connector_id"],
                    }
                )
                first_challenge = self.service.issue_relay_challenge()
                await websocket.send_json(first_challenge)
                message = await self._receive_message(websocket)
            session = await self._authenticate_session(
                websocket=websocket,
                challenge=first_challenge,
                message=message,
                connection_generation=connection_generation,
            )
            await self.registry.register(session)
            registered = True
            await websocket.send_json(
                {
                    "v": PROTOCOL_VERSION,
                    "type": "ready",
                    "connector_id": session.connector_id,
                    "instance_id": session.instance_id,
                    "capabilities": list(session.capabilities),
                }
            )
            await self._serve_session(session)
        except (AgentError, ProtocolError, ValueError):
            await self._safe_send_error(websocket)
            await websocket.close(code=1008)
        except WebSocketDisconnect:
            pass
        finally:
            if session is not None:
                removed = await self.registry.remove(session)
                if removed or not registered:
                    self.service.disconnect_relay(
                        instance_id=session.instance_id,
                        connection_generation=(
                            session.connection_generation
                        ),
                    )

    async def _authenticate_session(
        self,
        *,
        websocket: WebSocket,
        challenge: dict[str, str | int],
        message: dict[str, Any],
        connection_generation: str,
    ) -> AgentRelaySession:
        self._require_keys(
            message,
            {
                "v",
                "type",
                "challenge_id",
                "challenge",
                "connector_id",
                "instance_id",
                "context_epoch",
                "signature",
            },
        )
        if (
            message["v"] != PROTOCOL_VERSION
            or message["type"] != "authenticate"
            or message["challenge_id"] != challenge["challenge_id"]
            or message["challenge"] != challenge["challenge"]
        ):
            raise ProtocolError("relay authentication message is invalid")
        identity = self.service.authenticate_relay(
            challenge_id=message["challenge_id"],
            challenge=message["challenge"],
            connector_id=message["connector_id"],
            instance_id=message["instance_id"],
            context_epoch=message["context_epoch"],
            signature=message["signature"],
            connection_generation=connection_generation,
            capabilities=(),  # Set by caller from device profile.
        )
        device = self.service.store.get_device(identity["connector_id"])
        capabilities = tuple(
            capabilities_for_profile(device["capability_profile"])
        )
        return AgentRelaySession(
            websocket=websocket,
            connector_id=identity["connector_id"],
            instance_id=identity["instance_id"],
            context_epoch=identity["context_epoch"],
            connection_generation=identity["connection_generation"],
            capabilities=capabilities,
            capability_profile=device["capability_profile"],
        )

    async def _serve_session(self, session: AgentRelaySession) -> None:
        while True:
            message = await self._receive_message(session.websocket)
            if message.get("type") == "heartbeat":
                self._require_keys(
                    message,
                    {"v", "type", "context_epoch"},
                )
                if message["v"] != PROTOCOL_VERSION:
                    raise ProtocolError(
                        "relay protocol version is unsupported"
                    )
                self.service.heartbeat(
                    instance_id=session.instance_id,
                    connection_generation=session.connection_generation,
                    context_epoch=message["context_epoch"],
                    capabilities=session.capabilities,
                )
                session.context_epoch = max(
                    session.context_epoch,
                    message["context_epoch"],
                )
                continue
            if message.get("type") == "response":
                self._receive_response(session, message)
                continue
            raise ProtocolError("relay message type is unsupported")
    @staticmethod
    def _receive_response(
        session: AgentRelaySession,
        message: dict[str, Any],
    ) -> None:
        AgentRelayEndpoint._require_keys(
            message,
            {
                "v",
                "type",
                "request_id",
                "tool",
                "connector_id",
                "status",
                "result",
            },
        )
        if (
            message["v"] != PROTOCOL_VERSION
            or message["connector_id"] != session.connector_id
        ):
            raise ProtocolError("relay response is unsupported")
        request_id = str(message.get("request_id") or "")
        future = session.pending.get(request_id)
        if future is None or future.done():
            raise ProtocolError("relay response has no matching request")
        if message["status"] not in {"ok", "error"}:
            raise ProtocolError("relay response status is invalid")
        future.set_result(
            {
                "code": (
                    "ok" if message["status"] == "ok" else "device_error"
                ),
                **(
                    message.get("result") or {}
                    if message["status"] == "ok"
                    else {"error": message.get("result")}
                ),
            }
        )

    def _is_secure_connection(self, websocket: WebSocket) -> bool:
        if websocket.scope.get("scheme") == "wss":
            return True
        forwarded = websocket.headers.get("x-forwarded-proto", "")
        return self.config.trust_proxy_tls and forwarded.strip().lower() == "https"

    @staticmethod
    async def _receive_message(websocket: WebSocket) -> dict[str, Any]:
        text = await websocket.receive_text()
        if len(text.encode("utf-8")) > RELAY_MAX_MESSAGE_BYTES:
            raise ProtocolError("relay message is too large")
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProtocolError("relay message is not valid JSON") from exc
        if not isinstance(value, dict):
            raise ProtocolError("relay message must be an object")
        return value

    @staticmethod
    def _require_keys(
        value: dict[str, Any],
        required: set[str],
        *,
        allow_optional: set[str] | None = None,
    ) -> None:
        optional = allow_optional or set()
        if not required.issubset(value) or set(value) - required - optional:
            raise ProtocolError("relay message contains unsupported fields")

    @staticmethod
    async def _safe_send_error(websocket: WebSocket) -> None:
        try:
            await websocket.send_json(
                {
                    "v": PROTOCOL_VERSION,
                    "type": "error",
                    "code": "relay_rejected",
                }
            )
        except RuntimeError:
            pass
