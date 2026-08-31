from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse


_PLACEHOLDER_MARKERS = (
    "replace-with",
    "change-me",
    "changeme",
    "example-token",
)
_AUDIENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,95}$")


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _required_secret(name: str) -> str:
    value = os.getenv(name, "").strip()
    if len(value) < 32 or any(
        marker in value.lower() for marker in _PLACEHOLDER_MARKERS
    ):
        raise RuntimeError(
            f"{name} must contain a distinct non-placeholder secret "
            "with at least 32 characters"
        )
    return value


def _required_value(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _validate_http_url(
    value: str,
    *,
    field: str,
    allow_insecure_http: bool,
) -> str:
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError(f"{field} contains an invalid port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/mcp"
        or port == 0
    ):
        raise RuntimeError(
            f"{field} must be an absolute HTTP(S) URL ending in /mcp"
        )
    if parsed.scheme == "http" and not allow_insecure_http:
        raise RuntimeError(
            f"{field} uses HTTP. Set "
            "REMOTE_AGENT_ALLOW_INSECURE_HTTP=1 only for a private "
            "connector network, otherwise use HTTPS."
        )
    return value


def _validate_database_url(value: str, *, allow_sqlite_dev: bool) -> str:
    normalized = str(value or "").strip()
    lowered = normalized.lower()
    if lowered.startswith(("postgres://", "postgresql://")):
        return normalized
    if lowered.startswith("sqlite:///"):
        if not allow_sqlite_dev:
            raise RuntimeError(
                "SQLite is local-development/test only. Set "
                "REMOTE_AGENT_ALLOW_SQLITE_DEV=1 explicitly or configure "
                "a PostgreSQL REMOTE_AGENT_DATABASE_URL."
            )
        return normalized
    raise RuntimeError(
        "REMOTE_AGENT_DATABASE_URL must be a PostgreSQL URL or an explicitly "
        "allowed sqlite:/// URL"
    )


@dataclass(frozen=True)
class RemoteAgentConfig:
    database_url: str
    mcp_bearer_token: str
    hub_delegation_secret: str
    operator_bearer_token: str
    hub_audience: str
    private_mcp_url: str
    bind_host: str
    bind_port: int
    allowed_hosts: tuple[str, ...]
    allow_insecure_private_mcp: bool
    trust_proxy_tls: bool
    request_timeout_seconds: int
    heartbeat_timeout_seconds: int

    @classmethod
    def from_env(cls) -> "RemoteAgentConfig":
        allow_sqlite_dev = _env_flag("REMOTE_AGENT_ALLOW_SQLITE_DEV")
        allow_insecure_private_mcp = _env_flag(
            "REMOTE_AGENT_ALLOW_INSECURE_HTTP"
        )
        bind_port = int(os.getenv("REMOTE_AGENT_BIND_PORT", "3030"))
        if not 1 <= bind_port <= 65535:
            raise RuntimeError(
                "REMOTE_AGENT_BIND_PORT must be between 1 and 65535"
            )
        audience = _required_value("REMOTE_AGENT_HUB_AUDIENCE")
        if not _AUDIENCE_PATTERN.fullmatch(audience):
            raise RuntimeError("REMOTE_AGENT_HUB_AUDIENCE is invalid")
        allowed_hosts = tuple(
            item.strip()
            for item in os.getenv(
                "REMOTE_AGENT_ALLOWED_HOSTS",
                "",
            ).split(",")
            if item.strip()
        )
        if not allowed_hosts:
            raise RuntimeError("REMOTE_AGENT_ALLOWED_HOSTS is required")
        timeout = int(
            os.getenv(
                "REMOTE_AGENT_REQUEST_TIMEOUT_SECONDS",
                "60",
            )
        )
        if not 1 <= timeout <= 3600:
            raise RuntimeError(
                "REMOTE_AGENT_REQUEST_TIMEOUT_SECONDS must be 1-3600"
            )
        heartbeat_timeout = int(
            os.getenv(
                "REMOTE_AGENT_HEARTBEAT_TIMEOUT_SECONDS",
                "30",
            )
        )
        if not 1 <= heartbeat_timeout <= 3600:
            raise RuntimeError(
                "REMOTE_AGENT_HEARTBEAT_TIMEOUT_SECONDS must be 1-3600"
            )
        mcp_bearer_token = _required_secret(
            "REMOTE_AGENT_MCP_BEARER_TOKEN"
        )
        hub_delegation_secret = _required_secret(
            "REMOTE_AGENT_HUB_DELEGATION_SECRET"
        )
        operator_bearer_token = _required_secret(
            "REMOTE_AGENT_OPERATOR_BEARER_TOKEN"
        )
        if len(
            {
                mcp_bearer_token,
                hub_delegation_secret,
                operator_bearer_token,
            }
        ) != 3:
            raise RuntimeError(
                "Remote Agent bearer, delegation, and operator secrets "
                "must be distinct"
            )
        return cls(
            database_url=_validate_database_url(
                _required_value("REMOTE_AGENT_DATABASE_URL"),
                allow_sqlite_dev=allow_sqlite_dev,
            ),
            mcp_bearer_token=mcp_bearer_token,
            hub_delegation_secret=hub_delegation_secret,
            operator_bearer_token=operator_bearer_token,
            hub_audience=audience,
            private_mcp_url=_validate_http_url(
                _required_value("REMOTE_AGENT_PRIVATE_MCP_URL"),
                field="REMOTE_AGENT_PRIVATE_MCP_URL",
                allow_insecure_http=allow_insecure_private_mcp,
            ),
            bind_host=os.getenv(
                "REMOTE_AGENT_BIND_HOST",
                "127.0.0.1",
            ).strip(),
            bind_port=bind_port,
            allowed_hosts=allowed_hosts,
            allow_insecure_private_mcp=allow_insecure_private_mcp,
            trust_proxy_tls=_env_flag("REMOTE_AGENT_TRUST_PROXY_TLS"),
            request_timeout_seconds=timeout,
            heartbeat_timeout_seconds=heartbeat_timeout,
        )
