"""Delegation envelope acceptance, including the app-bound v4 form.

Phase 1 device enforcement needs to know which application a caller belongs to
without trusting a tool argument. v4 carries that as a Hub-signed assertion.
The connector must accept v4, keep accepting legacy v3, and fail closed when
the presented app id does not match what was signed.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import unittest

from remote_agent_connector.protocol import (
    ProtocolError,
    verify_delegation_headers,
)


SECRET = "d" * 48
AUDIENCE = "remote-agent-connector"


def _headers(
    *,
    client_id: str,
    scopes: tuple[str, ...],
    nonce: str,
    app_id: str | None = None,
    timestamp: int | None = None,
) -> dict[str, str]:
    stamp = str(int(time.time() if timestamp is None else timestamp))
    ordered = ",".join(sorted(scopes))
    if app_id:
        payload = (
            f"v4\n{AUDIENCE}\n{client_id}\n{app_id}\n"
            f"{stamp}\n{nonce}\n{ordered}"
        )
    else:
        payload = (
            f"v3\n{AUDIENCE}\n{client_id}\n{stamp}\n{nonce}\n{ordered}"
        )
    signature = hmac.new(
        SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    headers = {
        "x-mcp-hub-client-id": client_id,
        "x-mcp-hub-client-scopes": ordered,
        "x-mcp-hub-client-nonce": nonce,
        "x-mcp-hub-client-timestamp": stamp,
        "x-mcp-hub-client-signature": signature,
    }
    if app_id:
        headers["x-mcp-hub-app-id"] = app_id
    return headers


class DelegationEnvelopeTests(unittest.TestCase):
    def _verify(self, headers: dict[str, str]):
        return verify_delegation_headers(
            headers=headers,
            secret=SECRET,
            audience=AUDIENCE,
        )

    def test_v3_still_verifies_with_no_app_assertion(self):
        identity = self._verify(
            _headers(
                client_id="agy2api",
                scopes=("agent:read",),
                nonce="n" * 24,
            )
        )
        self.assertEqual(identity.client_id, "agy2api")
        self.assertEqual(identity.app_id, "")

    def test_v4_carries_the_app_assertion(self):
        identity = self._verify(
            _headers(
                client_id="agy2api",
                scopes=("agent:read",),
                nonce="m" * 24,
                app_id="codex",
            )
        )
        self.assertEqual(identity.app_id, "codex")

    def test_app_id_cannot_be_added_after_signing(self):
        """A caller cannot mint its own app scope from a v3 signature."""
        headers = _headers(
            client_id="agy2api",
            scopes=("agent:read",),
            nonce="p" * 24,
        )
        headers["x-mcp-hub-app-id"] = "codex"
        with self.assertRaises(ProtocolError):
            self._verify(headers)

    def test_wrong_app_id_fails_closed(self):
        headers = _headers(
            client_id="agy2api",
            scopes=("agent:read",),
            nonce="q" * 24,
            app_id="codex",
        )
        headers["x-mcp-hub-app-id"] = "hermes"
        with self.assertRaises(ProtocolError):
            self._verify(headers)

    def test_scope_escalation_invalidates_the_signature(self):
        headers = _headers(
            client_id="agy2api",
            scopes=("agent:read",),
            nonce="r" * 24,
            app_id="codex",
        )
        headers["x-mcp-hub-client-scopes"] = "agent:read,agent:write"
        with self.assertRaises(ProtocolError):
            self._verify(headers)

    def test_expired_envelope_is_rejected(self):
        headers = _headers(
            client_id="agy2api",
            scopes=("agent:read",),
            nonce="s" * 24,
            app_id="codex",
            timestamp=int(time.time()) - 600,
        )
        with self.assertRaises(ProtocolError):
            self._verify(headers)


if __name__ == "__main__":
    unittest.main()
