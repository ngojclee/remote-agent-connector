from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")
APP_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
CONNECTOR_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9][a-z0-9_.-]{0,62}$"
)
KEY_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
INSTANCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._*-]{0,63}$")
DISPLAY_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9 ._()#-]{1,80}$")
PLATFORM_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()#:/-]{0,63}$")
PROTOCOL_VERSION = 1
RELAY_MAX_MESSAGE_BYTES = 2 * 1024 * 1024
RESULT_MAX_BYTES = 1 * 1024 * 1024

# Phase 2 signed app assertion. The Hub is the only issuer; the connector only
# forwards the envelope, and the device verifies it against a pinned root.
APP_ASSERTION_SCHEMA_VERSION = (
    "business-mcp-remote-agent-app-assertion-v2"
)
APP_ASSERTION_ISSUER = "business-mcp-hub"
APP_ASSERTION_AUDIENCE = "remote-agent-device"
APP_ASSERTION_HEADER = "x-mcp-hub-app-assertion"
APP_ASSERTION_MAX_TTL_SECONDS = 300
APP_ASSERTION_CLOCK_SKEW_SECONDS = 5
# The connector must never stay waiting on a device call whose assertion can
# expire before that device verifies it. The Hub refuses to configure an
# assertion lifetime below 180 seconds, so this ceiling keeps the whole chain
# inside that floor with slack: 180 is greater than this value plus the skew
# allowance above plus the 5 second Hub delivery margin. Changing either side
# without the other fails a test in both repositories.
CONNECTOR_MAX_REQUEST_TIMEOUT_SECONDS = 165
ASSERTION_FIELDS = frozenset(
    {
        "schema_version",
        "issuer",
        "audience",
        "key_id",
        "client_id",
        "app_id",
        "connector_id",
        "scopes",
        "issued_at",
        "expires_at",
        "nonce",
        "request_id",
        "assertion_id",
        "signature",
    }
)

AGENT_READ_SCOPE = "agent:read"
AGENT_WRITE_SCOPE = "agent:write"
AGENT_TERMINAL_SCOPE = "agent:terminal"
AGENT_SSH_SCOPE = "agent:ssh"
AGENT_SKILLS_SCOPE = "agent:skills"
AGENT_MCP_SCOPE = "agent:mcp"
AGENT_CONTROL_SCOPE = "agent:control"
AGENT_SCOPES = frozenset(
    {
        AGENT_READ_SCOPE,
        AGENT_WRITE_SCOPE,
        AGENT_TERMINAL_SCOPE,
        AGENT_SSH_SCOPE,
        AGENT_SKILLS_SCOPE,
        AGENT_MCP_SCOPE,
        AGENT_CONTROL_SCOPE,
    }
)

READ_ONLY_CAPABILITIES = (
    "connector_health",
    "files_list",
    "files_stat",
    "files_search",
    "files_read",
    "files_download",
    "skills_list",
    "mcp_list_servers",
    "mcp_health",
    "skills_health",
)
READ_WRITE_CAPABILITIES = (
    *READ_ONLY_CAPABILITIES,
    "files_write",
    "files_delete",
    "files_move",
    "files_mkdir",
    "files_upload",
    # Materializing a skill writes instruction and asset files into an
    # approved root, so it is a mutation and never a read_only capability.
    "skills_materialize",
)
FULL_AGENT_CAPABILITIES = (
    *READ_WRITE_CAPABILITIES,
    "terminal_execute",
    "ssh_execute",
    "ssh_list_profiles",
    "skills_execute",
    "mcp_call",
)
CAPABILITIES_BY_PROFILE = {
    "read_only": frozenset(READ_ONLY_CAPABILITIES),
    "read_write": frozenset(READ_WRITE_CAPABILITIES),
    "full_agent": frozenset(FULL_AGENT_CAPABILITIES),
}


class ProtocolError(ValueError):
    """Raised when untrusted relay or delegated input is invalid."""


def parse_uuid(value: Any, *, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ProtocolError(f"{field} must be a UUID") from exc


def parse_connector_id(value: Any) -> str:
    connector_id = str(value or "").strip().lower()
    if not CONNECTOR_ID_PATTERN.fullmatch(connector_id):
        raise ProtocolError("connector_id is invalid")
    return connector_id


def parse_instance_id(value: Any) -> str:
    instance_id = str(value or "").strip()
    if not INSTANCE_ID_PATTERN.fullmatch(instance_id):
        raise ProtocolError("instance_id is invalid")
    return instance_id


def parse_client_id(value: Any) -> str:
    client_id = str(value or "").strip()
    if not CLIENT_ID_PATTERN.fullmatch(client_id):
        raise ProtocolError("client id is invalid")
    return client_id


def parse_nonce(value: Any) -> str:
    nonce = str(value or "").strip()
    if not NONCE_PATTERN.fullmatch(nonce):
        raise ProtocolError("delegation nonce is invalid")
    return nonce


def normalize_scopes(value: str | list[str] | None) -> tuple[str, ...]:
    raw = (
        str(value or "").split(",")
        if isinstance(value, str)
        else list(value or ())
    )
    scopes = tuple(
        sorted(
            {
                str(scope or "").strip()
                for scope in raw
                if str(scope or "").strip()
            }
        )
    )
    if not scopes or any(not SCOPE_PATTERN.fullmatch(s) for s in scopes):
        raise ProtocolError("delegated scopes are invalid")
    return scopes


def validate_agent_scopes(value: str | list[str] | None) -> tuple[str, ...]:
    scopes = normalize_scopes(value)
    if any(scope not in AGENT_SCOPES for scope in scopes):
        raise ProtocolError("delegated agent scopes are invalid")
    return scopes


def validate_display_label(value: Any) -> str:
    label = str(value or "").strip()
    if not DISPLAY_LABEL_PATTERN.fullmatch(label):
        raise ProtocolError("display_label is invalid")
    return label


def validate_platform(value: Any) -> str:
    platform = str(value or "").strip()
    if not platform or not PLATFORM_PATTERN.fullmatch(platform):
        raise ProtocolError("platform is invalid")
    return platform


def validate_capability_profile(value: Any) -> str:
    profile = str(value or "").strip().lower()
    if profile not in CAPABILITIES_BY_PROFILE:
        raise ProtocolError("capability_profile is invalid")
    return profile


def capabilities_for_profile(profile: str) -> tuple[str, ...]:
    return tuple(sorted(CAPABILITIES_BY_PROFILE[profile]))


def _b64decode(value: Any, *, field: str, expected_length: int) -> bytes:
    import base64

    encoded = str(value or "").strip()
    try:
        raw = base64.urlsafe_b64decode(
            encoded + "=" * (-len(encoded) % 4)
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f"{field} is not base64url") from exc
    if len(raw) != expected_length:
        raise ProtocolError(f"{field} has an invalid length")
    return raw


def parse_public_key(value: Any) -> bytes:
    return _b64decode(value, field="public_key", expected_length=32)


def parse_signature(value: Any) -> bytes:
    return _b64decode(value, field="signature", expected_length=64)


def b64url_encode(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def enrollment_payload(
    *,
    challenge_id: str,
    challenge: str,
    connector_id: str,
    enrollment_token: str,
    public_key: str,
) -> bytes:
    return (
        "remote-agent-enrollment-v1\n"
        f"{parse_uuid(challenge_id, field='challenge_id')}\n"
        f"{challenge}\n"
        f"{parse_connector_id(connector_id)}\n"
        f"{enrollment_token}\n"
        f"{public_key}"
    ).encode("utf-8")


def relay_auth_payload(
    *,
    challenge_id: str,
    challenge: str,
    connector_id: str,
    instance_id: str,
    context_epoch: int,
) -> bytes:
    return (
        "remote-agent-relay-auth-v1\n"
        f"{parse_uuid(challenge_id, field='challenge_id')}\n"
        f"{challenge}\n"
        f"{parse_connector_id(connector_id)}\n"
        f"{parse_instance_id(instance_id)}\n"
        f"{context_epoch}"
    ).encode("utf-8")


def verify_ed25519(
    *,
    public_key_b64: str,
    payload: bytes,
    signature_b64: str,
) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(
            parse_public_key(public_key_b64)
        ).verify(parse_signature(signature_b64), payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ProtocolError(
            "Ed25519 signature verification failed"
        ) from exc


def public_key_fingerprint(public_key_b64: str) -> str:
    return hashlib.sha256(
        parse_public_key(public_key_b64)
    ).hexdigest()[:16]


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    """Byte-exact JSON both the Hub and the device sign over."""
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _assertion_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"app assertion {field} is invalid")
    return value


def parse_app_assertion(value: Any) -> dict[str, Any]:
    """Strictly decode a Hub-signed app assertion.

    Two transports carry the same envelope: the connector receives it as a
    base64url header, and a device receives it as the relay frame's JSON
    object. Both forms are accepted here so the connector and the reference
    verifier share one strict parser. The cryptographic check stays
    device-side.
    """
    if isinstance(value, dict):
        decoded = value
    else:
        encoded = str(value or "").strip()
        if not encoded:
            raise ProtocolError("app assertion is missing")
        try:
            decoded = json.loads(
                base64.urlsafe_b64decode(
                    encoded + "=" * (-len(encoded) % 4)
                ).decode("utf-8")
            )
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ProtocolError("app assertion is not valid JSON") from exc
    if not isinstance(decoded, dict) or set(decoded) != ASSERTION_FIELDS:
        raise ProtocolError("app assertion fields are invalid")
    if decoded["schema_version"] != APP_ASSERTION_SCHEMA_VERSION:
        raise ProtocolError("app assertion schema is unsupported")
    if decoded["issuer"] != APP_ASSERTION_ISSUER:
        raise ProtocolError("app assertion issuer is invalid")
    if decoded["audience"] != APP_ASSERTION_AUDIENCE:
        raise ProtocolError("app assertion audience is invalid")
    if not KEY_ID_PATTERN.fullmatch(str(decoded["key_id"])):
        raise ProtocolError("app assertion key id is invalid")
    parse_client_id(decoded["client_id"])
    app_id = str(decoded["app_id"] or "").strip()
    if not APP_ID_PATTERN.fullmatch(app_id):
        raise ProtocolError("app assertion app id is invalid")
    parse_connector_id(decoded["connector_id"])
    normalize_scopes_result = validate_agent_scopes(decoded["scopes"])
    issued_at = _assertion_int(decoded["issued_at"], field="issued_at")
    expires_at = _assertion_int(decoded["expires_at"], field="expires_at")
    if expires_at <= issued_at:
        raise ProtocolError("app assertion expiry is invalid")
    if expires_at - issued_at > APP_ASSERTION_MAX_TTL_SECONDS:
        raise ProtocolError("app assertion lifetime is too long")
    parse_nonce(decoded["nonce"])
    parse_uuid(decoded["request_id"], field="request_id")
    parse_uuid(decoded["assertion_id"], field="assertion_id")
    parse_signature(decoded["signature"])
    return {
        **decoded,
        "app_id": app_id,
        "scopes": list(normalize_scopes_result),
    }


def canonical_delegation(
    *,
    audience: str,
    client_id: str,
    timestamp: int,
    nonce: str,
    scopes: str | list[str],
    app_id: str = "",
) -> bytes:
    normalized_client_id = parse_client_id(client_id)
    normalized_nonce = parse_nonce(nonce)
    normalized_scopes = validate_agent_scopes(scopes)
    normalized_app_id = str(app_id or "").strip()
    if normalized_app_id:
        # v4 binds the caller's application identity into the signature so a
        # device can approve per app without trusting a tool argument. The app
        # id is an assertion from the Hub; the device's own verified binding
        # stays authoritative.
        return (
            "v4\n"
            f"{audience}\n"
            f"{normalized_client_id}\n"
            f"{normalized_app_id}\n"
            f"{int(timestamp)}\n"
            f"{normalized_nonce}\n"
            f"{','.join(normalized_scopes)}"
        ).encode("utf-8")
    return (
        "v3\n"
        f"{audience}\n"
        f"{normalized_client_id}\n"
        f"{int(timestamp)}\n"
        f"{normalized_nonce}\n"
        f"{','.join(normalized_scopes)}"
    ).encode("utf-8")


@dataclass(frozen=True)
class DelegatedIdentity:
    client_id: str
    scopes: tuple[str, ...]
    nonce: str
    timestamp: int
    app_id: str = ""
    # Parsed Phase 2 envelope, or None for a legacy v3 caller and for a v4
    # caller whose Hub has no signing material configured yet (shadow mode).
    app_assertion: dict[str, Any] | None = None


def verify_delegation_headers(
    *,
    headers: Any,
    secret: str,
    audience: str,
    now: int | None = None,
    max_age_seconds: int = 90,
    require_app_assertion: bool = False,
) -> DelegatedIdentity:
    try:
        client_id = parse_client_id(
            headers.get("x-mcp-hub-client-id", "")
        )
        scopes = validate_agent_scopes(
            headers.get("x-mcp-hub-client-scopes", "")
        )
        nonce = parse_nonce(
            headers.get("x-mcp-hub-client-nonce", "")
        )
        timestamp = int(
            str(headers.get("x-mcp-hub-client-timestamp", "")).strip()
        )
        signature = str(
            headers.get("x-mcp-hub-client-signature", "")
        ).strip().lower()
    except (TypeError, ValueError, ProtocolError) as exc:
        raise ProtocolError(
            "delegated identity headers are invalid"
        ) from exc
    if not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise ProtocolError("delegation signature is invalid")
    current = int(time.time() if now is None else now)
    if abs(current - timestamp) > max(1, max_age_seconds):
        raise ProtocolError("delegation is expired")
    app_id = str(
        headers.get("x-mcp-hub-app-id", "") or ""
    ).strip()
    # The envelope form is decided by the presence of the app header, and the
    # signature must match that exact form. A v3 caller cannot attach an app id
    # after signing, and a v4 caller cannot drop or swap it, because either
    # change makes the recomputed payload differ from what was signed.
    payload = canonical_delegation(
        audience=audience,
        client_id=client_id,
        timestamp=timestamp,
        nonce=nonce,
        scopes=scopes,
        app_id=app_id,
    )
    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ProtocolError("delegation signature is invalid")
    app_assertion = None
    raw_assertion = str(
        headers.get(APP_ASSERTION_HEADER, "") or ""
    ).strip()
    if app_id:
        if raw_assertion:
            app_assertion = parse_app_assertion(raw_assertion)
            # The envelope must describe the identity the HMAC just proved.
            # Without this a connector could pair a valid signature with a
            # different caller's signed statement.
            matched = (
                app_assertion["client_id"] == client_id
                and app_assertion["app_id"] == app_id
                and app_assertion["nonce"] == nonce
                and tuple(app_assertion["scopes"]) == scopes
            )
            if not matched:
                raise ProtocolError(
                    "app assertion does not match the delegation"
                )
        elif require_app_assertion:
            raise ProtocolError("app assertion is required")
    elif raw_assertion:
        # An assertion without a v4 signature has no meaning, and accepting one
        # would let a caller present a binding it never signed for.
        raise ProtocolError("app assertion requires a v4 delegation")
    return DelegatedIdentity(
        client_id=client_id,
        scopes=scopes,
        nonce=nonce,
        timestamp=timestamp,
        app_id=app_id,
        app_assertion=app_assertion,
    )


def canonical_json_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
