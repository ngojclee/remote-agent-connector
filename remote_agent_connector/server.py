from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute

from . import __version__
from .config import RemoteAgentConfig
from .errors import AgentError
from .protocol import DelegatedIdentity, verify_delegation_headers
from .relay import AgentRelayEndpoint, AgentRelayRegistry
from .service import RemoteAgentService
from .store import RemoteAgentStore


READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
)
WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
)
CONTROL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
)


def _trusted_hostnames(allowed_hosts: tuple[str, ...]) -> list[str]:
    hostnames: set[str] = set()
    for authority in allowed_hosts:
        value = str(authority or "").strip()
        parsed = urlsplit(f"//{value}")
        if not parsed.hostname or parsed.username or parsed.password:
            raise RuntimeError("Remote Agent host allowlist is invalid")
        hostnames.add(parsed.hostname.lower())
    if not hostnames:
        raise RuntimeError("Remote Agent host allowlist is invalid")
    return sorted(hostnames)


class ConnectorTokenVerifier(TokenVerifier):
    def __init__(self, expected: str):
        self.expected = expected

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(str(token or ""), self.expected):
            return None
        return AccessToken(
            token="validated",
            client_id="business-mcp-hub",
            scopes=["mcp"],
        )


def create_app(
    config: RemoteAgentConfig | None = None,
    store: RemoteAgentStore | None = None,
) -> Starlette:
    resolved_config = config or RemoteAgentConfig.from_env()
    resolved_store = store or RemoteAgentStore(resolved_config.database_url)
    service = RemoteAgentService(config=resolved_config, store=resolved_store)
    relay_registry = AgentRelayRegistry()
    service.set_registry(relay_registry)
    relay_endpoint = AgentRelayEndpoint(
        config=resolved_config,
        service=service,
        registry=relay_registry,
    )
    server = FastMCP(
        name="Remote Agent Connector",
        instructions=(
            "Typed remote-agent device access with capability profiles. "
            "Each call targets an exact connector_id and authorized device."
        ),
        host=resolved_config.bind_host,
        port=resolved_config.bind_port,
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        auth=AuthSettings(
            issuer_url=resolved_config.private_mcp_url,
            resource_server_url=resolved_config.private_mcp_url,
            required_scopes=[],
        ),
        token_verifier=ConnectorTokenVerifier(
            resolved_config.mcp_bearer_token
        ),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(resolved_config.allowed_hosts),
            allowed_origins=[],
        ),
    )

    def delegated_identity() -> DelegatedIdentity:
        request = server.get_context().request_context.request
        try:
            return verify_delegation_headers(
                headers=request.headers,
                secret=resolved_config.hub_delegation_secret,
                audience=resolved_config.hub_audience,
            )
        except Exception as exc:
            raise ToolError("delegation_invalid") from None

    async def call_agent(
        *,
        tool: str,
        connector_id: str,
        arguments: dict[str, Any],
        identity: DelegatedIdentity,
        idempotency_key: str,
        instance_id: str | None = None,
    ) -> Any:
        try:
            return await service.device_command(
                identity=identity,
                tool=tool,
                connector_id=connector_id,
                arguments=arguments,
                idempotency_key=idempotency_key,
                instance_id=instance_id,
            )
        except AgentError as exc:
            raise ToolError(exc.code) from None

    @server.tool(annotations=READ_ONLY)
    async def connector_health(
        profile_id: str,
        idempotency_key: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Return connector health and platform metadata."""
        return await call_agent(
            tool="connector.health",
            connector_id=profile_id,
            arguments={},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def files_list(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        pattern: str | None = None,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """List approved files in a virtual root."""
        return await call_agent(
            tool="files.list",
            connector_id=profile_id,
            arguments={"root": root, "path": path, "pattern": pattern},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def files_stat(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Return file metadata without content."""
        return await call_agent(
            tool="files.stat",
            connector_id=profile_id,
            arguments={"root": root, "path": path},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def files_search(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        query: str,
        limit: int = 50,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Search inside approved files."""
        return await call_agent(
            tool="files.search",
            connector_id=profile_id,
            arguments={"root": root, "path": path, "query": query, "limit": limit},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def files_read(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        offset: int = 0,
        length: int | None = None,
        encoding: str = "text",
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Read bounded content from an approved file."""
        return await call_agent(
            tool="files.read",
            connector_id=profile_id,
            arguments={
                "root": root,
                "path": path,
                "offset": offset,
                "length": length,
                "encoding": encoding,
            },
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=WRITE)
    async def files_write(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        content: str,
        encoding: str = "text",
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Write bounded content into an approved root."""
        return await call_agent(
            tool="files.write",
            connector_id=profile_id,
            arguments={
                "root": root,
                "path": path,
                "content": content,
                "encoding": encoding,
            },
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=WRITE)
    async def files_delete(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Delete an approved file or empty directory."""
        return await call_agent(
            tool="files.delete",
            connector_id=profile_id,
            arguments={"root": root, "path": path},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=WRITE)
    async def files_move(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        destination: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Move an approved file within the same virtual root."""
        return await call_agent(
            tool="files.move",
            connector_id=profile_id,
            arguments={"root": root, "path": path, "destination": destination},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=WRITE)
    async def files_mkdir(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a directory in an approved root."""
        return await call_agent(
            tool="files.mkdir",
            connector_id=profile_id,
            arguments={"root": root, "path": path},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=WRITE)
    async def files_upload(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        content_base64: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Upload bounded binary content into an approved root."""
        return await call_agent(
            tool="files.upload",
            connector_id=profile_id,
            arguments={
                "root": root,
                "path": path,
                "content_base64": content_base64,
            },
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def files_download(
        profile_id: str,
        idempotency_key: str,
        root: str,
        path: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Download bounded binary content from an approved root."""
        return await call_agent(
            tool="files.download",
            connector_id=profile_id,
            arguments={"root": root, "path": path},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=CONTROL)
    async def terminal_execute(
        profile_id: str,
        idempotency_key: str,
        command: str,
        root: str | None = None,
        timeout_s: int = 300,
        cwd: str | None = None,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute an allowlisted command on the remote agent.

        ``root`` is optional and forwarded only when supplied, so a caller can
        dispatch a bare command. Callers that still send ``root`` keep working.
        """
        arguments: dict[str, Any] = {
            "command": command,
            "timeout_s": timeout_s,
            "cwd": cwd,
        }
        if root is not None:
            arguments["root"] = root
        return await call_agent(
            tool="terminal.execute",
            connector_id=profile_id,
            arguments=arguments,
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    # terminal_stream is intentionally not published. No layer implements it:
    # the Windows device has no dispatch arm for it and the Hub catalog omits
    # it. Publishing it produced a call that always failed and read like a
    # permissions problem. To restore, add the tool here, the capability in
    # protocol.py, and the entry in the Hub catalog.
    @server.tool(annotations=CONTROL)
    async def ssh_execute(
        profile_id: str,
        idempotency_key: str,
        host: str,
        command: str,
        root: str | None = None,
        timeout_s: int = 300,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a command through an approved SSH profile.

        ``host`` is the canonical host selector. ``root`` is accepted for
        backward compatibility but is not used for SSH execution.
        """
        return await call_agent(
            tool="ssh.execute",
            connector_id=profile_id,
            arguments={
                "root": root,
                "host": host,
                "command": command,
                "timeout_s": timeout_s,
            },
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def ssh_list_profiles(
        profile_id: str,
        idempotency_key: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """List approved SSH profiles on the device."""
        return await call_agent(
            tool="ssh.list_profiles",
            connector_id=profile_id,
            arguments={},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def skills_list(
        profile_id: str,
        idempotency_key: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """List approved client skills."""
        return await call_agent(
            tool="skills.list",
            connector_id=profile_id,
            arguments={},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=WRITE)
    async def skills_materialize(
        profile_id: str,
        idempotency_key: str,
        skill_id: str,
        target_root: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Materialize approved instruction and reference files into a root.

        This is a mutation: it writes files under ``target_root`` and requires
        both the skills and write grants. The device currently answers with an
        explicit not-implemented error, so the tool is reachable but performs no
        work until the Windows Connector ships it.
        """
        return await call_agent(
            tool="skills.materialize",
            connector_id=profile_id,
            arguments={"skill_id": skill_id, "target_root": target_root},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=CONTROL)
    async def skills_execute(
        profile_id: str,
        idempotency_key: str,
        skill_id: str,
        arguments: dict[str, Any] | None = None,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute an approved client skill through typed tools."""
        return await call_agent(
            tool="skills.execute",
            connector_id=profile_id,
            arguments={"skill_id": skill_id, "arguments": arguments or {}},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def mcp_list_servers(
        profile_id: str,
        idempotency_key: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """List approved local MCP servers."""
        return await call_agent(
            tool="mcp.list_servers",
            connector_id=profile_id,
            arguments={},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=CONTROL)
    async def mcp_call(
        profile_id: str,
        idempotency_key: str,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Call an approved tool on a local MCP server."""
        return await call_agent(
            tool="mcp.call",
            connector_id=profile_id,
            arguments={
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments": arguments or {},
            },
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def mcp_health(
        profile_id: str,
        idempotency_key: str,
        server_id: str | None = None,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Report discovered local MCP servers, not live connectivity.

        The device discovers server entries from other harnesses' config files
        and never launches them, so a reported server is configuration that was
        seen, not a process that is running or reachable. Treat
        ``connected: false`` as the expected answer today rather than a fault.
        """
        return await call_agent(
            tool="mcp.health",
            connector_id=profile_id,
            arguments={"server_id": server_id},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    @server.tool(annotations=READ_ONLY)
    async def skills_health(
        profile_id: str,
        idempotency_key: str,
        instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Return client skill health."""
        return await call_agent(
            tool="skills.health",
            connector_id=profile_id,
            arguments={},
            identity=delegated_identity(),
            idempotency_key=idempotency_key,
            instance_id=instance_id,
        )

    # connector_restart_mcp is removed rather than stubbed. The device only
    # discovers MCP servers that other harnesses own and never launches them,
    # so there is no connector-owned process to restart. Implementing it would
    # mean controlling another application's processes. It returns only when a
    # connector-owned supervisor exists and marks its servers as managed.
    async def health(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "service": "remote-agent-connector",
                "version": __version__,
            }
        )

    def operator_authorized(request: Request) -> bool:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(
            header.removeprefix("Bearer "),
            resolved_config.operator_bearer_token,
        )

    async def issue_enrollment(request: Request) -> JSONResponse:
        if not operator_authorized(request):
            return JSONResponse({"code": "unauthorized"}, status_code=401)
        try:
            body = await request.json()
            result = service.issue_enrollment_token(
                connector_id=body["connector_id"],
                capability_profile=body["capability_profile"],
                display_label=body["display_label"],
                expires_in_seconds=int(body.get("expires_in_seconds", 600)),
            )
            return JSONResponse(result, status_code=201)
        except Exception:
            return JSONResponse(
                {"code": "invalid_enrollment_request"},
                status_code=400,
            )

    async def revoke_device(request: Request) -> JSONResponse:
        if not operator_authorized(request):
            return JSONResponse({"code": "unauthorized"}, status_code=401)
        connector_id = request.path_params["connector_id"]
        try:
            return JSONResponse(
                service.revoke_device(connector_id=connector_id)
            )
        except AgentError as exc:
            return JSONResponse({"code": exc.code}, status_code=404)

    async def rename_device(request: Request) -> JSONResponse:
        if not operator_authorized(request):
            return JSONResponse({"code": "unauthorized"}, status_code=401)
        connector_id = request.path_params["connector_id"]
        try:
            body = await request.json()
            return JSONResponse(
                service.rename_device(
                    connector_id=connector_id,
                    display_label=body["display_label"],
                )
            )
        except AgentError as exc:
            return JSONResponse(
                {"code": exc.code},
                status_code=(
                    404 if exc.code == "device_not_found" else 400
                ),
            )

    async def delete_device(request: Request) -> JSONResponse:
        if not operator_authorized(request):
            return JSONResponse({"code": "unauthorized"}, status_code=401)
        connector_id = request.path_params["connector_id"]
        try:
            return JSONResponse(
                service.delete_revoked_device(connector_id=connector_id)
            )
        except AgentError as exc:
            return JSONResponse(
                {"code": exc.code},
                status_code=(
                    404
                    if exc.code == "device_not_found"
                    else 409
                    if exc.code == "device_not_revoked"
                    else 400
                ),
            )

    async def list_devices(request: Request) -> JSONResponse:
        if not operator_authorized(request):
            return JSONResponse({"code": "unauthorized"}, status_code=401)
        return JSONResponse(service.operator_devices())

    async def list_agents(request: Request) -> JSONResponse:
        if not operator_authorized(request):
            return JSONResponse({"code": "unauthorized"}, status_code=401)
        return JSONResponse(service.online_agents())

    async def operator_audit(request: Request) -> JSONResponse:
        if not operator_authorized(request):
            return JSONResponse({"code": "unauthorized"}, status_code=401)
        try:
            limit = int(request.query_params.get("limit", "100"))
        except ValueError:
            return JSONResponse({"code": "invalid_limit"}, status_code=400)
        return JSONResponse(
            {"events": service.store.audit_events(limit=limit)}
        )

    mcp_app = server.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: Starlette):
        async with mcp_app.router.lifespan_context(mcp_app):
            yield

    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/operator/enrollment-tokens", issue_enrollment, methods=["POST"]),
            Route("/operator/devices/{connector_id}/revoke", revoke_device, methods=["POST"]),
            Route("/operator/devices/{connector_id}", rename_device, methods=["PUT"]),
            Route("/operator/devices/{connector_id}", delete_device, methods=["DELETE"]),
            Route("/operator/devices", list_devices, methods=["GET"]),
            Route("/agents", list_agents, methods=["GET"]),
            Route("/operator/audit", operator_audit, methods=["GET"]),
            WebSocketRoute("/relay", relay_endpoint),
            Mount("/", app=mcp_app),
        ],
        lifespan=lifespan,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=_trusted_hostnames(resolved_config.allowed_hosts),
    )
    app.state.remote_agent_config = resolved_config
    app.state.remote_agent_store = resolved_store
    app.state.remote_agent_service = service
    app.state.remote_agent_relay_registry = relay_registry
    app.state.mcp_server = server
    return app
