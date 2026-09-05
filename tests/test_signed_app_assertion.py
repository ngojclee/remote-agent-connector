"""Phase 2 signed app assertion acceptance for the Remote Agent connector.

Two layers are covered. The connector must parse and pair the envelope strictly
without ever holding signing material, and the reference device verifier must
reject every tampering, expiry, replay, and key-state case the contract names.
``tests/fixtures/app_assertion_vector.json`` mirrors the published contract
vector so both repositories check the same bytes.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from remote_agent_connector.app_assertion import (
    AppAssertionError,
    AppAssertionVerifier,
    TrustAnchor,
)
from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.errors import AgentError
from remote_agent_connector.protocol import (
    APP_ASSERTION_HEADER,
    DelegatedIdentity,
    ProtocolError,
    b64url_encode,
    capabilities_for_profile,
    canonical_json_bytes,
    parse_app_assertion,
    verify_delegation_headers,
)
from remote_agent_connector.relay import AgentRelaySession
from remote_agent_connector.service import RemoteAgentService
from remote_agent_connector.store import RemoteAgentStore


SECRET = "d" * 48
AUDIENCE = "remote-agent-connector"
DEVICE_CONNECTOR_ID = "agy2api-10.11.1.1"
FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "app_assertion_vector.json"
)


def _load_vector() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _delegation_headers(
    *,
    client_id: str,
    scopes: tuple[str, ...],
    nonce: str,
    app_id: str = "",
    assertion: str = "",
) -> dict[str, str]:
    stamp = str(int(time.time()))
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
    digest = hmac.new(
        SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    headers = {
        "x-mcp-hub-client-id": client_id,
        "x-mcp-hub-client-scopes": ordered,
        "x-mcp-hub-client-nonce": nonce,
        "x-mcp-hub-client-timestamp": stamp,
        "x-mcp-hub-client-signature": digest,
    }
    if app_id:
        headers["x-mcp-hub-app-id"] = app_id
    if assertion:
        headers[APP_ASSERTION_HEADER] = assertion
    return headers


class _Keyring:
    """Deterministic test keys. These are never live signing material."""

    def __init__(self, *, issued_at: int):
        self.issued_at = issued_at
        self.root = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.active = Ed25519PrivateKey.from_private_bytes(
            bytes(range(33, 65))
        )
        self.retiring = Ed25519PrivateKey.from_private_bytes(
            bytes(range(65, 97))
        )
        self.revoked = Ed25519PrivateKey.from_private_bytes(
            bytes(range(97, 129))
        )
        self.foreign_root = Ed25519PrivateKey.from_private_bytes(
            bytes(range(129, 161))
        )

    @staticmethod
    def _public(key: Ed25519PrivateKey) -> str:
        return b64url_encode(key.public_key().public_bytes_raw())

    def keyset(
        self,
        *,
        root=None,
        root_key_id="root-local-test",
        next_root=None,
    ):
        unsigned = {
            "schema_version": (
                "business-mcp-remote-agent-app-keyset-v1"
            ),
            "issuer": "business-mcp-hub",
            "root_key_id": root_key_id,
            "issued_at": self.issued_at,
            "expires_at": self.issued_at + 3600,
            "keys": [
                {
                    "key_id": "sign-a",
                    "public_key": self._public(self.active),
                    "not_before": self.issued_at - 600,
                    "not_after": self.issued_at + 3600,
                    "status": "active",
                },
                {
                    "key_id": "sign-retiring",
                    "public_key": self._public(self.retiring),
                    "not_before": self.issued_at - 7200,
                    "not_after": self.issued_at + 1800,
                    "status": "retiring",
                },
                {
                    "key_id": "sign-revoked",
                    "public_key": self._public(self.revoked),
                    "not_before": self.issued_at - 7200,
                    "not_after": self.issued_at + 1800,
                    "status": "revoked",
                },
            ],
        }
        if next_root is not None:
            # next_root must sit inside the signed body, otherwise the root
            # signature does not cover it and adoption is meaningless.
            unsigned["next_root"] = next_root
        signer = root or self.root
        return {
            **unsigned,
            "signature": b64url_encode(
                signer.sign(canonical_json_bytes(unsigned))
            ),
        }

    def assertion(self, *, key_name="active", key_id="sign-a", **overrides):
        envelope = {
            "schema_version": (
                "business-mcp-remote-agent-app-assertion-v2"
            ),
            "issuer": "business-mcp-hub",
            "audience": "remote-agent-device",
            "key_id": key_id,
            "client_id": "v4-shadow-codex-20260905",
            "app_id": "codex",
            "connector_id": DEVICE_CONNECTOR_ID,
            "scopes": ["agent:read"],
            "issued_at": self.issued_at,
            "expires_at": self.issued_at + 90,
            "nonce": "n" * 24,
            "request_id": "3f2b7c1a-9d4e-4f60-8a21-6c5e2b0d7f13",
            "assertion_id": "b1e6f2a4-7c3d-4e5f-9a0b-2c4d6e8f0a1b",
        }
        envelope.update(overrides)
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        return {
            **envelope,
            "signature": b64url_encode(
                getattr(self, key_name).sign(canonical_json_bytes(unsigned))
            ),
        }


class AssertionParsingTests(unittest.TestCase):
    def setUp(self):
        self.vector = _load_vector()
        self.assertion = self.vector["assertion"]
        self.encoded = b64url_encode(canonical_json_bytes(self.assertion))

    def test_published_vector_hashes_are_pinned(self):
        """The fixture must stay byte-identical to the published contract."""
        unsigned = {
            k: v for k, v in self.assertion.items() if k != "signature"
        }
        self.assertEqual(
            hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
            self.vector["canonical_payload_sha256_assertion"],
        )
        keyset = self.vector["keyset"]
        unsigned_keyset = {
            k: v for k, v in keyset.items() if k != "signature"
        }
        self.assertEqual(
            hashlib.sha256(
                canonical_json_bytes(unsigned_keyset)
            ).hexdigest(),
            self.vector["canonical_payload_sha256_keyset"],
        )

    def test_vector_envelope_parses(self):
        parsed = parse_app_assertion(self.encoded)
        self.assertEqual(parsed["app_id"], "codex")
        self.assertEqual(parsed["request_id"], self.assertion["request_id"])
        self.assertEqual(parsed["scopes"], ["agent:read"])

    def test_rejects_malformed_envelopes(self):
        cases = {
            "missing field": {
                k: v for k, v in self.assertion.items() if k != "nonce"
            },
            "extra field": {**self.assertion, "extra": "x"},
            "wrong issuer": {**self.assertion, "issuer": "someone-else"},
            "wrong audience": {**self.assertion, "audience": "other"},
            "wrong schema": {**self.assertion, "schema_version": "v1"},
            "empty app id": {**self.assertion, "app_id": ""},
            "overlong ttl": {
                **self.assertion,
                "expires_at": self.assertion["issued_at"] + 3600,
            },
            "bad key id": {**self.assertion, "key_id": "BAD KEY"},
            "bad scopes": {**self.assertion, "scopes": ["not-an-agent-scope"]},
            "bad request id": {**self.assertion, "request_id": "nope"},
        }
        for label, mutated in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError):
                    parse_app_assertion(
                        b64url_encode(canonical_json_bytes(mutated))
                    )

    def test_rejects_unusable_encodings(self):
        for label, value in (
            ("empty", ""),
            ("not base64", "!!!"),
            ("not json", b64url_encode(b"plain text")),
            ("not object", b64url_encode(b"[1,2]")),
        ):
            with self.subTest(raw=label):
                with self.assertRaises(ProtocolError):
                    parse_app_assertion(value)


class DelegationPairingTests(unittest.TestCase):
    def setUp(self):
        self.assertion = _load_vector()["assertion"]
        self.encoded = b64url_encode(
            canonical_json_bytes(self.assertion)
        )

    def _verify(self, headers, **kwargs):
        return verify_delegation_headers(
            headers=headers,
            secret=SECRET,
            audience=AUDIENCE,
            **kwargs,
        )

    def test_v3_identity_is_unchanged(self):
        identity = self._verify(
            _delegation_headers(
                client_id="agy2api",
                scopes=("agent:read",),
                nonce="v" * 24,
            )
        )
        self.assertEqual(identity.app_id, "")
        self.assertIsNone(identity.app_assertion)

    def test_v4_with_matching_assertion_is_accepted(self):
        identity = self._verify(
            _delegation_headers(
                client_id=self.assertion["client_id"],
                scopes=tuple(self.assertion["scopes"]),
                nonce=self.assertion["nonce"],
                app_id=self.assertion["app_id"],
                assertion=self.encoded,
            )
        )
        self.assertEqual(
            identity.app_assertion["request_id"],
            self.assertion["request_id"],
        )

    def test_assertion_must_match_the_verified_identity(self):
        for field, value in (
            ("client_id", "someone-else"),
            ("app_id", "hermes"),
            ("nonce", "z" * 24),
        ):
            with self.subTest(field=field):
                mutated = {**self.assertion, field: value}
                with self.assertRaises(ProtocolError):
                    self._verify(
                        _delegation_headers(
                            client_id=self.assertion["client_id"],
                            scopes=tuple(self.assertion["scopes"]),
                            nonce=self.assertion["nonce"],
                            app_id=self.assertion["app_id"],
                            assertion=b64url_encode(
                                canonical_json_bytes(mutated)
                            ),
                        )
                    )

    def test_scope_mismatch_is_rejected(self):
        mutated = {
            **self.assertion,
            "scopes": ["agent:read", "agent:write"],
        }
        with self.assertRaises(ProtocolError):
            self._verify(
                _delegation_headers(
                    client_id=self.assertion["client_id"],
                    scopes=tuple(self.assertion["scopes"]),
                    nonce=self.assertion["nonce"],
                    app_id=self.assertion["app_id"],
                    assertion=b64url_encode(canonical_json_bytes(mutated)),
                )
            )

    def test_shadow_mode_allows_an_unsigned_v4_call(self):
        identity = self._verify(
            _delegation_headers(
                client_id="agy2api",
                scopes=("agent:read",),
                nonce="s" * 24,
                app_id="codex",
            )
        )
        self.assertEqual(identity.app_id, "codex")
        self.assertIsNone(identity.app_assertion)

    def test_require_mode_rejects_an_unsigned_v4_call(self):
        with self.assertRaises(ProtocolError):
            self._verify(
                _delegation_headers(
                    client_id="agy2api",
                    scopes=("agent:read",),
                    nonce="r" * 24,
                    app_id="codex",
                ),
                require_app_assertion=True,
            )

    def test_assertion_without_v4_is_rejected(self):
        with self.assertRaises(ProtocolError):
            self._verify(
                _delegation_headers(
                    client_id="agy2api",
                    scopes=("agent:read",),
                    nonce="q" * 24,
                    assertion=self.encoded,
                )
            )


class DeviceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.vector = _load_vector()
        self.now = int(self.vector["pinned_clock_unix_seconds"])
        self.keyring = _Keyring(issued_at=self.vector["assertion"]["issued_at"])
        self.local_verifier = AppAssertionVerifier(
            anchor=TrustAnchor(
                root_key_id="root-local-test",
                root_public_key=b64url_encode(
                    self.keyring.root.public_key().public_bytes_raw()
                ),
            ),
            connector_id=DEVICE_CONNECTOR_ID,
            clock=lambda: self.now,
        )
        self.local_keys = self.local_verifier.verify_keyset(
            self.keyring.keyset()
        )

    def _expected(self, assertion):
        return {
            "request_id": assertion["request_id"],
            "expected_client_id": assertion["client_id"],
            "expected_app_id": assertion["app_id"],
            "expected_scopes": tuple(assertion["scopes"]),
        }

    def _fresh(self):
        return AppAssertionVerifier(
            anchor=self.local_verifier.anchor,
            connector_id=DEVICE_CONNECTOR_ID,
            clock=lambda: self.now,
        )

    def test_published_vector_verifies_end_to_end(self):
        verifier = AppAssertionVerifier(
            anchor=TrustAnchor(
                root_key_id=self.vector["root_key_id"],
                root_public_key=self.vector["root_public_key"],
            ),
            connector_id=DEVICE_CONNECTOR_ID,
            clock=lambda: self.now,
        )
        keys = verifier.verify_keyset(self.vector["keyset"])
        assertion = self.vector["assertion"]
        verified = verifier.verify(
            assertion, keys=keys, **self._expected(assertion)
        )
        self.assertEqual(verified.app_id, "codex")
        self.assertEqual(verified.key_id, "sign-vector-a")
        self.assertEqual(verified.scopes, ("agent:read",))

    def test_binding_mismatches_are_rejected(self):
        assertion = self.keyring.assertion()
        cases = {
            "app_id": {
                **self._expected(assertion),
                "expected_app_id": "hermes",
            },
            "client_id": {
                **self._expected(assertion),
                "expected_client_id": "other",
            },
            "scopes": {
                **self._expected(assertion),
                "expected_scopes": ("agent:read", "agent:write"),
            },
            "request_id": {
                **self._expected(assertion),
                "request_id": "00000000-0000-4000-8000-000000000000",
            },
        }
        for label, expected in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(AppAssertionError) as caught:
                    self._fresh().verify(
                        assertion, keys=self.local_keys, **expected
                    )
                self.assertEqual(
                    caught.exception.code, "app_identity_mismatch"
                )

    def test_other_device_assertion_is_rejected(self):
        assertion = self.keyring.assertion(
            connector_id="agy2api-10.11.1.9"
        )
        with self.assertRaises(AppAssertionError) as caught:
            self._fresh().verify(
                assertion,
                keys=self.local_keys,
                **self._expected(assertion),
            )
        self.assertEqual(caught.exception.code, "app_identity_mismatch")

    def test_expired_assertion_is_rejected(self):
        assertion = self.keyring.assertion()
        verifier = self._fresh()
        self.now = assertion["expires_at"]
        with self.assertRaises(AppAssertionError) as caught:
            verifier.verify(
                assertion, keys=self.local_keys, **self._expected(assertion)
            )
        self.assertEqual(caught.exception.code, "app_assertion_expired")

    def test_replayed_assertion_is_rejected(self):
        assertion = self.keyring.assertion()
        verifier = self._fresh()
        verifier.verify(
            assertion, keys=self.local_keys, **self._expected(assertion)
        )
        with self.assertRaises(AppAssertionError) as caught:
            verifier.verify(
                assertion,
                keys=self.local_keys,
                **self._expected(assertion),
            )
        self.assertEqual(caught.exception.code, "app_assertion_replayed")

    def test_replay_window_clears_after_expiry(self):
        assertion = self.keyring.assertion()
        verifier = self._fresh()
        verifier.verify(
            assertion, keys=self.local_keys, **self._expected(assertion)
        )
        self.now = assertion["expires_at"] + 1
        with self.assertRaises(AppAssertionError) as caught:
            verifier.verify(
                assertion,
                keys=self.local_keys,
                **self._expected(assertion),
            )
        self.assertEqual(caught.exception.code, "app_assertion_expired")

    def test_unknown_key_id_is_rejected(self):
        assertion = self.keyring.assertion(key_id="sign-unknown")
        with self.assertRaises(AppAssertionError) as caught:
            self._fresh().verify(
                assertion, keys=self.local_keys, **self._expected(assertion)
            )
        self.assertEqual(
            caught.exception.code, "app_assertion_unverified"
        )

    def test_revoked_key_is_rejected(self):
        assertion = self.keyring.assertion(
            key_name="revoked", key_id="sign-revoked"
        )
        with self.assertRaises(AppAssertionError) as caught:
            self._fresh().verify(
                assertion, keys=self.local_keys, **self._expected(assertion)
            )
        self.assertEqual(
            caught.exception.code, "app_assertion_unverified"
        )

    def test_rotation_overlap_accepts_active_and_retiring(self):
        for key_name, key_id in (
            ("active", "sign-a"),
            ("retiring", "sign-retiring"),
        ):
            with self.subTest(key=key_id):
                assertion = self.keyring.assertion(
                    key_name=key_name, key_id=key_id
                )
                verified = self._fresh().verify(
                    assertion,
                    keys=self.local_keys,
                    **self._expected(assertion),
                )
                self.assertEqual(verified.key_id, key_id)

    def test_key_outside_its_window_is_rejected(self):
        assertion = self.keyring.assertion(
            key_name="retiring", key_id="sign-retiring"
        )
        expired_keys = {
            "sign-retiring": {
                **self.local_keys["sign-retiring"],
                "not_after": self.now - 1,
            }
        }
        with self.assertRaises(AppAssertionError) as caught:
            self._fresh().verify(
                assertion, keys=expired_keys, **self._expected(assertion)
            )
        self.assertEqual(
            caught.exception.code, "app_assertion_unverified"
        )

    def test_keyset_from_an_unpinned_root_is_rejected(self):
        forged = self.keyring.keyset(root=self.keyring.foreign_root)
        with self.assertRaises(AppAssertionError) as caught:
            self.local_verifier.verify_keyset(forged)
        self.assertEqual(
            caught.exception.code, "app_assertion_unverified"
        )

    def test_keyset_with_a_different_root_id_is_rejected(self):
        with self.assertRaises(AppAssertionError):
            self.local_verifier.verify_keyset(
                {**self.keyring.keyset(), "root_key_id": "root-other"}
            )

    def test_next_root_is_adoptable_only_from_a_signed_keyset(self):
        candidate = {
            "key_id": "root-next",
            "public_key": b64url_encode(
                self.keyring.foreign_root.public_key().public_bytes_raw()
            ),
            "not_before": self.now,
            "not_after": self.now + 86400,
        }
        signed = self.keyring.keyset(next_root=candidate)
        self.assertEqual(self.local_verifier.pending_root(signed), candidate)
        # The same envelope signed by a root this device never pinned must not
        # be able to introduce a replacement root.
        forged = self.keyring.keyset(
            root=self.keyring.foreign_root, next_root=candidate
        )
        with self.assertRaises(AppAssertionError) as caught:
            self.local_verifier.pending_root(forged)
        self.assertEqual(
            caught.exception.code, "app_assertion_unverified"
        )

    def test_anchor_refuses_a_non_public_root(self):
        with self.assertRaises(ValueError):
            TrustAnchor(root_key_id="root", root_public_key="not-a-key")


class _AnsweringWebSocket:
    def __init__(self):
        self.sent: list[dict] = []
        self._session = None

    async def send_json(self, message: dict) -> None:
        self.sent.append(message)
        future = self._session.pending.get(message["request_id"])
        if future is not None and not future.done():
            future.set_result({"code": "ok"})


class _StubRegistry:
    def __init__(self, session):
        self._session = session

    async def get_exact(self, *, connector_id: str, instance_id: str):
        if (
            self._session is not None
            and self._session.connector_id == connector_id
            and self._session.instance_id == instance_id
        ):
            return self._session
        return None


class RelayFrameTests(unittest.TestCase):
    def setUp(self):
        self.vector = _load_vector()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = None

    def tearDown(self):
        if self.store is not None:
            self.store.close()
        self.temp_dir.cleanup()

    def _dispatch(self, *, identity: DelegatedIdentity, tool="connector.health", connector_id=DEVICE_CONNECTOR_ID):
        config = RemoteAgentConfig(
            database_url=f"sqlite:///{Path(self.temp_dir.name) / 'frames.sqlite'}",
            mcp_bearer_token="m" * 48,
            hub_delegation_secret=SECRET,
            operator_bearer_token="o" * 48,
            hub_audience=AUDIENCE,
            private_mcp_url="http://127.0.0.1:3030/mcp",
            bind_host="127.0.0.1",
            bind_port=3030,
            allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
            allow_insecure_private_mcp=True,
            trust_proxy_tls=False,
            request_timeout_seconds=5,
            heartbeat_timeout_seconds=30,
        )
        self.store = RemoteAgentStore(config.database_url)
        service = RemoteAgentService(config=config, store=self.store)
        now = datetime.now(timezone.utc)
        self.store.enroll_device(
            connector_id=DEVICE_CONNECTOR_ID,
            public_key="k" * 43,
            display_label="Frames",
            capability_profile="full_agent",
            platform="Windows 11",
            now=now,
        )
        self.store.upsert_presence(
            connector_id=DEVICE_CONNECTOR_ID,
            instance_id="instance-01",
            connection_generation="generation-01",
            context_epoch=1,
            capabilities=tuple(capabilities_for_profile("full_agent")),
            now=now,
        )
        websocket = _AnsweringWebSocket()
        session = AgentRelaySession(
            websocket=websocket,
            connector_id=DEVICE_CONNECTOR_ID,
            instance_id="instance-01",
            context_epoch=1,
            connection_generation="generation-01",
            capabilities=tuple(capabilities_for_profile("full_agent")),
            capability_profile="full_agent",
        )
        websocket._session = session
        service.set_registry(_StubRegistry(session))

        async def call():
            return await service.device_command(
                identity=identity,
                tool=tool,
                connector_id=connector_id,
                arguments={},
                idempotency_key=f"frame-{identity.app_id or 'v3'}-{len(websocket.sent)}",
            )

        result = asyncio.run(call())
        return result, list(websocket.sent)

    def test_signed_assertion_reaches_the_device_verbatim(self):
        assertion = self.vector["assertion"]
        identity = DelegatedIdentity(
            client_id=assertion["client_id"],
            scopes=tuple(assertion["scopes"]),
            nonce=assertion["nonce"],
            timestamp=int(time.time()),
            app_id=assertion["app_id"],
            app_assertion=parse_app_assertion(
                b64url_encode(canonical_json_bytes(assertion))
            ),
        )
        result, frames = self._dispatch(identity=identity)
        self.assertEqual(result["code"], "ok")
        self.assertEqual(len(frames), 1)
        frame = frames[0]
        # The device correlates the envelope to exactly this relay request.
        self.assertEqual(frame["request_id"], assertion["request_id"])
        self.assertEqual(frame["app_id"], "codex")
        self.assertEqual(frame["app_assertion"], assertion)
        self.assertNotIn(SECRET, json.dumps(frame))

    def test_shadow_v4_keeps_the_phase_one_statement(self):
        identity = DelegatedIdentity(
            client_id="agy2api",
            scopes=("agent:read",),
            nonce="s" * 24,
            timestamp=int(time.time()),
            app_id="codex",
        )
        _, frames = self._dispatch(identity=identity)
        frame = frames[0]
        self.assertEqual(
            frame["app_assertion"],
            {
                "source": "hub-delegation-v4",
                "verified": True,
                "client_id": "agy2api",
            },
        )
        self.assertNotEqual(
            frame["request_id"],
            self.vector["assertion"]["request_id"],
        )

    def test_v3_frame_is_unchanged(self):
        identity = DelegatedIdentity(
            client_id="agy2api",
            scopes=("agent:read",),
            nonce="v" * 24,
            timestamp=int(time.time()),
        )
        _, frames = self._dispatch(identity=identity)
        self.assertEqual(
            set(frames[0]),
            {
                "v",
                "type",
                "request_id",
                "tool",
                "connector_id",
                "arguments",
            },
        )

    def test_assertion_for_another_device_is_not_forwarded(self):
        assertion = {
            **self.vector["assertion"],
            "connector_id": "agy2api-10.11.1.9",
        }
        identity = DelegatedIdentity(
            client_id="agy2api",
            scopes=("agent:read",),
            nonce="n" * 24,
            timestamp=int(time.time()),
            app_id="codex",
            app_assertion=assertion,
        )
        with self.assertRaises(AgentError) as caught:
            self._dispatch(identity=identity)
        self.assertEqual(
            caught.exception.code, "app_assertion_connector_mismatch"
        )


if __name__ == "__main__":
    unittest.main()
