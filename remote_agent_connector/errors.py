from __future__ import annotations

from typing import Any


class AgentError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


_RELAY_DIAGNOSTICS: dict[str, dict[str, Any]] = {
    "relay_upgrade_failed": {
        "stage": "upgrade",
        "retryable": True,
        "message": "Relay WebSocket upgrade failed.",
    },
    "relay_challenge_timeout": {
        "stage": "challenge",
        "retryable": True,
        "message": "Relay challenge timed out.",
    },
    "enrollment_token_invalid": {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment token is invalid.",
    },
    "enrollment_token_expired": {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment token has expired.",
    },
    "enrollment_token_consumed": {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment token has already been consumed.",
    },
    "connector_id_mismatch": {
        "stage": "enrollment",
        "retryable": False,
        "message": "Connector ID does not match the enrollment.",
    },
    "enrollment_signature_invalid": {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment signature is invalid.",
    },
    "enrollment_challenge_invalid": {
        "stage": "enrollment",
        "retryable": False,
        "message": "Enrollment challenge is invalid.",
    },
    "device_already_enrolled": {
        "stage": "enrollment",
        "retryable": False,
        "message": "This connector is already enrolled.",
    },
    "device_revoked": {
        "stage": "authentication",
        "retryable": False,
        "message": "This device has been revoked.",
    },
    "relay_authentication_failed": {
        "stage": "authentication",
        "retryable": False,
        "message": "Relay authentication failed.",
    },
    "relay_ready_failed": {
        "stage": "ready",
        "retryable": True,
        "message": "Relay session could not become ready.",
    },
    "relay_protocol_error": {
        "stage": "session",
        "retryable": False,
        "message": "Relay message is invalid.",
    },
}


def relay_diagnostic(
    code: str,
    *,
    stage: str | None = None,
) -> dict[str, Any]:
    """Return a bounded, allowlisted diagnostic for the device client.

    The payload is deliberately built from fixed strings. It never includes
    exception text or any value received in a relay frame, so secrets and
    handshake material cannot leak through an error response.
    """
    requested = str(code or "")
    if requested == "invalid_challenge":
        requested = (
            "enrollment_challenge_invalid"
            if stage == "enrollment"
            else "relay_authentication_failed"
        )
    elif requested == "invalid_signature":
        requested = (
            "enrollment_signature_invalid"
            if stage == "enrollment"
            else "relay_authentication_failed"
        )
    elif requested == "capabilities_not_granted":
        requested = "relay_ready_failed"
    elif requested not in _RELAY_DIAGNOSTICS:
        requested = (
            "relay_ready_failed"
            if stage == "ready"
            else "relay_protocol_error"
        )
    spec = _RELAY_DIAGNOSTICS[requested]
    payload = {
        "v": 1,
        "type": "error",
        "code": requested,
        "stage": spec["stage"],
        "retryable": bool(spec["retryable"]),
        "message": spec["message"],
    }
    if requested in {
        "relay_authentication_failed",
        "relay_protocol_error",
    } and stage in {"authentication", "session", "enrollment"}:
        payload["stage"] = stage
    elif requested == "device_revoked" and stage in {
        "enrollment",
        "authentication",
    }:
        payload["stage"] = stage
    return payload
