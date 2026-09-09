from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.testclient import TestClient

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.errors import AgentError, relay_diagnostic
from remote_agent_connector.server import create_app
from remote_agent_connector.service import RemoteAgentService
from remote_agent_connector.store import RemoteAgentStore


NOW = datetime(2026, 9, 9, 15, 0, 0, tzinfo=timezone.utc)


def _config(database_path: Path, *, handshake_timeout: int = 1):
    return RemoteAgentConfig(
        database_url=f"sqlite:///{database_path}",
        mcp_bearer_token="m" * 48,
        hub_delegation_secret="d" * 48,
        operator_bearer_token="o" * 48,
        hub_audience="remote-agent-connector",
        private_mcp_url="http://127.0.0.1:3030/mcp",
        bind_host="127.0.0.1",
        bind_port=3030,
        allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
        allow_insecure_private_mcp=True,
        trust_proxy_tls=True,
        request_timeout_seconds=2,
        heartbeat_timeout_seconds=30,
        relay_handshake_timeout_seconds=handshake_timeout,
    )


def _secure_headers() -> dict[str, str]:
    return {
        "Host": "localhost:3030",
        "X-Forwarded-Proto": "https",
    }


class RelayDiagnosticTests(unittest.TestCase):
    def test_diagnostics_are_allowlisted_and_redacted(self):
        sensitive = (
            "raw-enrollment-token",
            "public-key-material",
            "signature-material",
            "challenge-material",
            "request-body-value",
            "Bearer operator-secret",
            "C:\\private\\path",
        )
        codes = (
            "relay_upgrade_failed",
            "relay_challenge_timeout",
            "enrollment_token_invalid",
            "enrollment_token_expired",
            "enrollment_token_consumed",
            "connector_id_mismatch",
            "enrollment_signature_invalid",
            "device_already_enrolled",
            "device_revoked",
            "relay_authentication_failed",
            "relay_ready_failed",
        )
        for code in codes:
            with self.subTest(code=code):
                payload = relay_diagnostic(code)
                self.assertEqual(
                    set(payload),
                    {
                        "v",
                        "type",
                        "code",
                        "stage",
                        "retryable",
                        "message",
                    },
                )
                rendered = json.dumps(payload)
                for value in sensitive:
                    self.assertNotIn(value, rendered)

    def test_enrollment_token_statuses_are_distinguished_without_raw_token(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RemoteAgentStore(
                f"sqlite:///{Path(directory) / 'relay.sqlite'}"
            )
            try:
                status, record = store.consume_enrollment_token_detailed(
                    raw_token="unknown-token",
                    connector_id="agy2api-01",
                    now=NOW,
                )
                self.assertEqual((status, record), ("invalid", None))

                mismatch = store.issue_enrollment_token(
                    connector_id="agy2api-01",
                    capability_profile="full_agent",
                    display_label="AGY2API 01",
                    expires_in_seconds=600,
                    now=NOW,
                )
                status, record = store.consume_enrollment_token_detailed(
                    raw_token=mismatch,
                    connector_id="agy2api-02",
                    now=NOW,
                )
                self.assertEqual((status, record), ("connector_mismatch", None))

                expired = store.issue_enrollment_token(
                    connector_id="agy2api-01",
                    capability_profile="full_agent",
                    display_label="Expired",
                    expires_in_seconds=1,
                    now=NOW,
                )
                status, record = store.consume_enrollment_token_detailed(
                    raw_token=expired,
                    connector_id="agy2api-01",
                    now=NOW + timedelta(seconds=1),
                )
                self.assertEqual((status, record), ("expired", None))

                accepted = store.issue_enrollment_token(
                    connector_id="agy2api-01",
                    capability_profile="full_agent",
                    display_label="Accepted",
                    expires_in_seconds=600,
                    now=NOW,
                )
                status, record = store.consume_enrollment_token_detailed(
                    raw_token=accepted,
                    connector_id="agy2api-01",
                    now=NOW,
                )
                self.assertEqual(status, "accepted")
                self.assertNotIn(accepted, json.dumps(record))
                status, record = store.consume_enrollment_token_detailed(
                    raw_token=accepted,
                    connector_id="agy2api-01",
                    now=NOW,
                )
                self.assertEqual((status, record), ("consumed", None))
            finally:
                store.close()

    def test_timeout_returns_bounded_challenge_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RemoteAgentStore(
                f"sqlite:///{Path(directory) / 'relay.sqlite'}"
            )
            try:
                app = create_app(
                    _config(
                        Path(directory) / "relay.sqlite",
                        handshake_timeout=1,
                    ),
                    store,
                )
                with TestClient(app) as client:
                    with client.websocket_connect(
                        "/relay",
                        headers=_secure_headers(),
                    ) as websocket:
                        self.assertEqual(
                            websocket.receive_json()["type"],
                            "challenge",
                        )
                        error = websocket.receive_json()
                self.assertEqual(error["code"], "relay_challenge_timeout")
                self.assertEqual(error["stage"], "challenge")
                self.assertTrue(error["retryable"])
            finally:
                store.close()

    def test_invalid_token_diagnostic_does_not_echo_enrollment_frame(self):
        raw_token = "raw-enrollment-token"
        public_key = "public-key-material"
        signature = "signature-material"
        with tempfile.TemporaryDirectory() as directory:
            store = RemoteAgentStore(
                f"sqlite:///{Path(directory) / 'relay.sqlite'}"
            )
            try:
                app = create_app(
                    _config(Path(directory) / "relay.sqlite"),
                    store,
                )
                with TestClient(app) as client:
                    with client.websocket_connect(
                        "/relay",
                        headers=_secure_headers(),
                    ) as websocket:
                        challenge = websocket.receive_json()
                        websocket.send_json(
                            {
                                "v": 1,
                                "type": "enroll",
                                "challenge_id": challenge["challenge_id"],
                                "challenge": challenge["challenge"],
                                "connector_id": "agy2api-01",
                                "enrollment_token": raw_token,
                                "public_key": public_key,
                                "signature": signature,
                            }
                        )
                        error = websocket.receive_json()
                self.assertEqual(error["code"], "enrollment_token_invalid")
                rendered = json.dumps(error)
                for value in (raw_token, public_key, signature):
                    self.assertNotIn(value, rendered)
            finally:
                store.close()

    def test_connector_mismatch_is_reported_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "relay.sqlite"
            store = RemoteAgentStore(f"sqlite:///{database_path}")
            token = store.issue_enrollment_token(
                connector_id="agy2api-01",
                capability_profile="full_agent",
                display_label="AGY2API 01",
                expires_in_seconds=600,
                now=NOW,
            )
            try:
                app = create_app(_config(database_path), store)
                with TestClient(app) as client:
                    with client.websocket_connect(
                        "/relay",
                        headers=_secure_headers(),
                    ) as websocket:
                        challenge = websocket.receive_json()
                        websocket.send_json(
                            {
                                "v": 1,
                                "type": "enroll",
                                "challenge_id": challenge["challenge_id"],
                                "challenge": challenge["challenge"],
                                "connector_id": "agy2api-02",
                                "enrollment_token": token,
                                "public_key": "k" * 43,
                                "signature": "s" * 86,
                            }
                        )
                        error = websocket.receive_json()
                self.assertEqual(error["code"], "connector_id_mismatch")
                self.assertEqual(error["stage"], "enrollment")
            finally:
                store.close()

    def test_malformed_authentication_maps_to_auth_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RemoteAgentStore(
                f"sqlite:///{Path(directory) / 'relay.sqlite'}"
            )
            try:
                app = create_app(
                    _config(Path(directory) / "relay.sqlite"),
                    store,
                )
                with TestClient(app) as client:
                    with client.websocket_connect(
                        "/relay",
                        headers=_secure_headers(),
                    ) as websocket:
                        challenge = websocket.receive_json()
                        websocket.send_json(
                            {
                                "v": 1,
                                "type": "unexpected",
                                "challenge_id": challenge["challenge_id"],
                                "challenge": challenge["challenge"],
                                "connector_id": "unknown-01",
                                "instance_id": "instance-01",
                                "context_epoch": 1,
                                "signature": "signature",
                            }
                        )
                        error = websocket.receive_json()
                self.assertEqual(
                    error["code"],
                    "relay_authentication_failed",
                )
                self.assertEqual(error["stage"], "authentication")
            finally:
                store.close()

    def test_unknown_and_revoked_devices_have_different_auth_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "relay.sqlite"
            store = RemoteAgentStore(f"sqlite:///{database_path}")
            config = _config(database_path)
            service = RemoteAgentService(
                config=config,
                store=store,
                clock=lambda: NOW,
            )
            try:
                challenge = store.create_challenge(now=NOW)
                with self.assertRaises(AgentError) as unknown:
                    service.authenticate_relay(
                        challenge_id=challenge["challenge_id"],
                        challenge=challenge["challenge"],
                        connector_id="unknown-01",
                        instance_id="instance-01",
                        context_epoch=1,
                        signature="signature",
                        connection_generation="generation-01",
                        capabilities=(),
                    )
                self.assertEqual(
                    unknown.exception.code,
                    "relay_authentication_failed",
                )

                store.enroll_device(
                    connector_id="revoked-01",
                    public_key="k" * 43,
                    display_label="Revoked",
                    capability_profile="full_agent",
                    platform="Windows 11",
                    now=NOW,
                )
                store.revoke_device(
                    connector_id="revoked-01",
                    now=NOW,
                )
                challenge = store.create_challenge(now=NOW)
                with self.assertRaises(AgentError) as revoked:
                    service.authenticate_relay(
                        challenge_id=challenge["challenge_id"],
                        challenge=challenge["challenge"],
                        connector_id="revoked-01",
                        instance_id="instance-01",
                        context_epoch=1,
                        signature="signature",
                        connection_generation="generation-01",
                        capabilities=(),
                    )
                self.assertEqual(revoked.exception.code, "device_revoked")
            finally:
                store.close()

    def test_nginx_upgrade_contract_is_bounded_and_strict(self):
        config = (
            Path(__file__).resolve().parents[1]
            / "deploy"
            / "remote-agent-relay.nginx.conf"
        ).read_text(encoding="utf-8")
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", config)
        self.assertIn("proxy_intercept_errors on;", config)
        self.assertIn("error_page 400 401 403 404 405 408 426", config)
        self.assertIn('"code":"relay_upgrade_failed"', config)
        self.assertNotIn("proxy_ssl_verify off", config)
        self.assertNotIn("ssl_verify_client off", config)


if __name__ == "__main__":
    unittest.main()
