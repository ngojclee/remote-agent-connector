from __future__ import annotations

from enum import Enum
from typing import Any


class AgentError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


RELAY_ERROR_CONTRACT = "business-mcp-remote-agent-relay-error-v1"


class RelayErrorCode(str, Enum):
    """Stable public codes emitted at the relay boundary.

    Internal exception keywords are intentionally not the wire contract. The
    relay maps them into this closed set before anything reaches a device.
    """

    RELAY_TLS_FAILED = "relay_tls_failed"
    RELAY_UPGRADE_FAILED = "relay_upgrade_failed"
    RELAY_CHALLENGE_TIMEOUT = "relay_challenge_timeout"
    RELAY_CHALLENGE_INVALID = "relay_challenge_invalid"
    ENROLLMENT_TOKEN_INVALID = "enrollment_token_invalid"
    ENROLLMENT_TOKEN_EXPIRED = "enrollment_token_expired"
    ENROLLMENT_TOKEN_CONSUMED = "enrollment_token_consumed"
    CONNECTOR_ID_MISMATCH = "connector_id_mismatch"
    ENROLLMENT_SIGNATURE_INVALID = "enrollment_signature_invalid"
    ENROLLMENT_CHALLENGE_INVALID = "enrollment_challenge_invalid"
    DEVICE_ALREADY_ENROLLED = "device_already_enrolled"
    DEVICE_REVOKED = "device_revoked"
    RELAY_AUTHENTICATION_FAILED = "relay_authentication_failed"
    RELAY_READY_FAILED = "relay_ready_failed"
    RELAY_PROTOCOL_ERROR = "relay_protocol_error"


_RELAY_DIAGNOSTICS: dict[RelayErrorCode, dict[str, Any]] = {
    RelayErrorCode.RELAY_TLS_FAILED: {
        "stage": "tls",
        "retryable": True,
        "message": "Relay TLS validation failed.",
        "transport_only": True,
    },
    RelayErrorCode.RELAY_UPGRADE_FAILED: {
        "stage": "upgrade",
        "retryable": True,
        "message": "Relay WebSocket upgrade failed.",
    },
    RelayErrorCode.RELAY_CHALLENGE_TIMEOUT: {
        "stage": "challenge",
        "retryable": True,
        "message": "Relay challenge timed out.",
    },
    RelayErrorCode.RELAY_CHALLENGE_INVALID: {
        "stage": "challenge",
        "retryable": False,
        "message": "Relay challenge is invalid.",
    },
    RelayErrorCode.ENROLLMENT_TOKEN_INVALID: {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment token is invalid.",
    },
    RelayErrorCode.ENROLLMENT_TOKEN_EXPIRED: {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment token has expired.",
    },
    RelayErrorCode.ENROLLMENT_TOKEN_CONSUMED: {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment token has already been consumed.",
    },
    RelayErrorCode.CONNECTOR_ID_MISMATCH: {
        "stage": "enrollment",
        "retryable": False,
        "message": "Connector ID does not match the enrollment.",
    },
    RelayErrorCode.ENROLLMENT_SIGNATURE_INVALID: {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment signature is invalid.",
    },
    RelayErrorCode.ENROLLMENT_CHALLENGE_INVALID: {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment challenge is invalid.",
    },
    RelayErrorCode.DEVICE_ALREADY_ENROLLED: {
        "stage": "enrollment",
        "retryable": False,
        "message": "This connector is already enrolled.",
    },
    RelayErrorCode.DEVICE_REVOKED: {
        "stage": "authentication",
        "retryable": False,
        "message": "This device has been revoked.",
    },
    RelayErrorCode.RELAY_AUTHENTICATION_FAILED: {
        "stage": "authentication",
        "retryable": False,
        "message": "Relay authentication failed.",
    },
    RelayErrorCode.RELAY_READY_FAILED: {
        "stage": "ready",
        "retryable": True,
        "message": "Relay session could not become ready.",
    },
    RelayErrorCode.RELAY_PROTOCOL_ERROR: {
        "stage": "session",
        "retryable": False,
        "message": "Relay message is invalid.",
    },
}

RELAY_ERROR_CODES = tuple(code.value for code in _RELAY_DIAGNOSTICS)


_INTERNAL_ERROR_MAP: dict[str, RelayErrorCode] = {
    "invalid_challenge": RelayErrorCode.RELAY_CHALLENGE_INVALID,
    "invalid_signature": RelayErrorCode.RELAY_AUTHENTICATION_FAILED,
    "capabilities_not_granted": RelayErrorCode.RELAY_READY_FAILED,
}


def _canonical_relay_code(
    code: RelayErrorCode | str,
    *,
    stage: str | None,
) -> RelayErrorCode:
    if isinstance(code, RelayErrorCode):
        canonical = code
    else:
        raw = str(code or "")
        canonical = _INTERNAL_ERROR_MAP.get(raw)
        if canonical is None:
            try:
                canonical = RelayErrorCode(raw)
            except ValueError:
                canonical = (
                    RelayErrorCode.RELAY_READY_FAILED
                    if stage == "ready"
                    else RelayErrorCode.RELAY_PROTOCOL_ERROR
                )
    if canonical == RelayErrorCode.RELAY_CHALLENGE_INVALID:
        if stage == "enrollment":
            return RelayErrorCode.ENROLLMENT_CHALLENGE_INVALID
    elif canonical == RelayErrorCode.RELAY_AUTHENTICATION_FAILED:
        if stage == "enrollment":
            return RelayErrorCode.ENROLLMENT_SIGNATURE_INVALID
    return canonical


def relay_diagnostic(
    code: RelayErrorCode | str,
    *,
    stage: str | None = None,
) -> dict[str, Any]:
    """Return the versioned, bounded relay error contract.

    The payload is deliberately built from fixed strings. It never includes
    exception text or any value received in a relay frame, so secrets and
    handshake material cannot leak through an error response.
    """
    canonical = _canonical_relay_code(code, stage=stage)
    spec = _RELAY_DIAGNOSTICS[canonical]
    payload = {
        "v": 1,
        "type": "error",
        "error_contract": RELAY_ERROR_CONTRACT,
        "code": canonical.value,
        "stage": spec["stage"],
        "retryable": bool(spec["retryable"]),
        "message": spec["message"],
    }
    if canonical in {
        RelayErrorCode.RELAY_AUTHENTICATION_FAILED,
        RelayErrorCode.RELAY_PROTOCOL_ERROR,
    } and stage in {"authentication", "session", "enrollment"}:
        payload["stage"] = stage
    elif canonical == RelayErrorCode.DEVICE_REVOKED and stage in {
        "enrollment",
        "authentication",
    }:
        payload["stage"] = stage
    return payload


def relay_error_contract() -> dict[str, Any]:
    """Return a JSON-safe description of the public code vocabulary."""
    return {
        "contract": RELAY_ERROR_CONTRACT,
        "protocol_version": 1,
        "codes": [
            {
                "code": code.value,
                "stage": spec["stage"],
                "retryable": bool(spec["retryable"]),
                "message": spec["message"],
                **(
                    {"transport_only": True}
                    if spec.get("transport_only")
                    else {}
                ),
            }
            for code, spec in _RELAY_DIAGNOSTICS.items()
        ],
    }
