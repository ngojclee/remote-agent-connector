"""Reference device-side verification of Hub-signed app assertions.

This module is the executable form of the Phase 2 contract. A device pins one
root public key at install time, fetches the published keyset, and verifies
every per-request assertion against it. The connector delegation secret and all
private material stay out of the picture entirely.

The Windows connector implements the same rules in Rust. Any change here must be
mirrored there before enforcement is turned on.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from .protocol import (
    APP_ASSERTION_AUDIENCE,
    APP_ASSERTION_ISSUER,
    APP_ASSERTION_MAX_TTL_SECONDS,
    APP_ASSERTION_SCHEMA_VERSION,
    ProtocolError,
    canonical_json_bytes,
    parse_app_assertion,
    parse_public_key,
    parse_signature,
)


KEYSET_SCHEMA_VERSION = "business-mcp-remote-agent-app-keyset-v1"
KEYSET_MAX_LIFETIME_SECONDS = 24 * 60 * 60
DEFAULT_CLOCK_SKEW_SECONDS = 5
USABLE_KEY_STATUSES = frozenset({"active", "retiring"})


class AppAssertionError(ValueError):
    """A public-safe verification failure. Codes are stable contract values."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TrustAnchor:
    """The single public value a device pins at install time."""

    root_key_id: str
    root_public_key: str

    def __post_init__(self) -> None:
        if not str(self.root_key_id or "").strip():
            raise ValueError("root_key_id is required")
        parse_public_key(self.root_public_key)


@dataclass(frozen=True)
class VerifiedAppAssertion:
    app_id: str
    client_id: str
    connector_id: str
    scopes: tuple[str, ...]
    key_id: str
    request_id: str
    assertion_id: str
    expires_at: int


def _verify_signature(
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
        raise AppAssertionError("app_assertion_unverified") from exc


class AppAssertionVerifier:
    """Verify keysets and per-request assertions for one enrolled device."""

    def __init__(
        self,
        *,
        anchor: TrustAnchor,
        connector_id: str,
        clock: Callable[[], float] = time.time,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
        seen_limit: int = 4096,
    ):
        self.anchor = anchor
        self.connector_id = str(connector_id)
        self.clock = clock
        self.clock_skew_seconds = max(0, int(clock_skew_seconds))
        self.seen_limit = max(1, int(seen_limit))
        self._seen: "OrderedDict[str, int]" = OrderedDict()

    def verify_keyset(self, keyset: Any) -> dict[str, dict[str, Any]]:
        """Return the keys this device may trust from a published keyset.

        A keyset is only trusted when the pinned root signed it. A ``next_root``
        is reported back only because it appeared inside that signed envelope,
        which is what makes root rotation safe without accepting an arbitrary
        root over the network.
        """
        if not isinstance(keyset, dict):
            raise AppAssertionError("app_assertion_unverified")
        if keyset.get("schema_version") != KEYSET_SCHEMA_VERSION:
            raise AppAssertionError("app_assertion_unverified")
        if keyset.get("root_key_id") != self.anchor.root_key_id:
            raise AppAssertionError("app_assertion_unverified")
        unsigned = {
            key: value for key, value in keyset.items() if key != "signature"
        }
        _verify_signature(
            public_key_b64=self.anchor.root_public_key,
            payload=canonical_json_bytes(unsigned),
            signature_b64=str(keyset.get("signature") or ""),
        )
        current = int(self.clock())
        issued_at = unsigned.get("issued_at")
        expires_at = unsigned.get("expires_at")
        if (
            not isinstance(issued_at, int)
            or not isinstance(expires_at, int)
            or expires_at <= issued_at
            or expires_at - issued_at > KEYSET_MAX_LIFETIME_SECONDS
            or current < issued_at - self.clock_skew_seconds
        ):
            raise AppAssertionError("app_assertion_unverified")
        keys: dict[str, dict[str, Any]] = {}
        raw_keys = unsigned.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise AppAssertionError("app_assertion_unverified")
        for item in raw_keys:
            if not isinstance(item, dict) or set(item) != {
                "key_id",
                "public_key",
                "not_before",
                "not_after",
                "status",
            }:
                raise AppAssertionError("app_assertion_unverified")
            key_id = str(item["key_id"])
            if key_id in keys:
                raise AppAssertionError("app_assertion_unverified")
            parse_public_key(item["public_key"])
            keys[key_id] = item
        return keys

    def verify(
        self,
        assertion: Any,
        *,
        keys: dict[str, dict[str, Any]],
        request_id: str,
        expected_client_id: str,
        expected_app_id: str,
        expected_scopes: tuple[str, ...] | list[str],
    ) -> VerifiedAppAssertion:
        """Verify one relayed assertion against this device's own binding."""
        try:
            parsed = parse_app_assertion(assertion)
        except ProtocolError as exc:
            raise AppAssertionError(str(exc)) from exc
        current = int(self.clock())
        if parsed["expires_at"] <= current:
            raise AppAssertionError("app_assertion_expired")
        if parsed["issued_at"] > current + self.clock_skew_seconds:
            raise AppAssertionError("app_assertion_unverified")
        if parsed["expires_at"] - parsed["issued_at"] > (
            APP_ASSERTION_MAX_TTL_SECONDS
        ):
            raise AppAssertionError("app_assertion_unverified")
        key = keys.get(str(parsed["key_id"]))
        if (
            key is None
            or key["status"] not in USABLE_KEY_STATUSES
            or current < key["not_before"] - self.clock_skew_seconds
            or current >= key["not_after"]
        ):
            # Unknown, revoked, or outside its overlap window.
            raise AppAssertionError("app_assertion_unverified")
        unsigned = {
            key_name: value
            for key_name, value in parsed.items()
            if key_name != "signature"
        }
        _verify_signature(
            public_key_b64=key["public_key"],
            payload=canonical_json_bytes(unsigned),
            signature_b64=parsed["signature"],
        )
        if (
            parsed["schema_version"] != APP_ASSERTION_SCHEMA_VERSION
            or parsed["issuer"] != APP_ASSERTION_ISSUER
            or parsed["audience"] != APP_ASSERTION_AUDIENCE
        ):
            raise AppAssertionError("app_assertion_unverified")
        if parsed["connector_id"] != self.connector_id:
            raise AppAssertionError("app_identity_mismatch")
        if (
            parsed["client_id"] != expected_client_id
            or parsed["app_id"] != expected_app_id
        ):
            raise AppAssertionError("app_identity_mismatch")
        if tuple(parsed["scopes"]) != tuple(sorted(expected_scopes)):
            raise AppAssertionError("app_identity_mismatch")
        if parsed["request_id"] != str(request_id):
            raise AppAssertionError("app_identity_mismatch")
        self._reject_replay(parsed["assertion_id"], parsed["expires_at"])
        return VerifiedAppAssertion(
            app_id=parsed["app_id"],
            client_id=parsed["client_id"],
            connector_id=parsed["connector_id"],
            scopes=tuple(parsed["scopes"]),
            key_id=parsed["key_id"],
            request_id=parsed["request_id"],
            assertion_id=parsed["assertion_id"],
            expires_at=parsed["expires_at"],
        )

    def _reject_replay(self, assertion_id: str, expires_at: int) -> None:
        """Refuse an assertion id already accepted inside its lifetime."""
        current = int(self.clock())
        stale = [
            seen_id
            for seen_id, seen_expiry in self._seen.items()
            if seen_expiry <= current
        ]
        for seen_id in stale:
            self._seen.pop(seen_id, None)
        if assertion_id in self._seen:
            raise AppAssertionError("app_assertion_replayed")
        self._seen[assertion_id] = expires_at
        while len(self._seen) > self.seen_limit:
            self._seen.popitem(last=False)

    def pending_root(self, keyset: Any) -> dict[str, Any] | None:
        """Return a replacement root only if the pinned root signed it."""
        self.verify_keyset(keyset)
        candidate = keyset.get("next_root")
        if candidate is None:
            return None
        if not isinstance(candidate, dict) or set(candidate) != {
            "key_id",
            "public_key",
            "not_before",
            "not_after",
        }:
            raise AppAssertionError("app_assertion_unverified")
        parse_public_key(candidate["public_key"])
        current = int(self.clock())
        if (
            not isinstance(candidate["not_before"], int)
            or not isinstance(candidate["not_after"], int)
            or candidate["not_after"] <= candidate["not_before"]
            or current >= candidate["not_after"]
        ):
            raise AppAssertionError("app_assertion_unverified")
        return candidate
