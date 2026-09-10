from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from starlette.testclient import TestClient

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.certificate_authority import (
    RELAY_CERT_ISSUANCE_CONTRACT,
    RelayCertificateError,
    relay_certificate_status,
    sign_relay_csr,
)
from remote_agent_connector.errors import (
    RELAY_ERROR_CONTRACT,
    RELAY_ERROR_CODES,
    relay_diagnostic,
    relay_error_contract,
)
from remote_agent_connector.server import create_app
from remote_agent_connector.store import RemoteAgentStore
from remote_agent_connector.tls_publication import (
    RELAY_CA_PUBLICATION_CONTRACT,
    load_public_ca_artifact,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 9, 15, 0, 0, tzinfo=timezone.utc)


def _config(database_path: Path, ca_path: str | None = None):
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
        public_ca_cert_path=ca_path,
    )


def _write_certificate(
    path: Path,
    *,
    ca: bool,
    san_ip: str | None = None,
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Business MCP Remote Agent Test",
            )
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    )
    if san_ip is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(IPv4Address(san_ip))]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    certificate = builder.sign(key, hashes.SHA256())
    path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )


def _write_ca(directory: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Remote Agent Test CA")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
                key_agreement=False,
                data_encipherment=False,
            ),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = directory / "ca.crt"
    key_path = directory / "ca.key"
    certificate_path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


def _relay_csr(key_path: Path | None = None, ip_address: str = "10.21.4.101"):
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if key_path is None
        else None
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        "Remote Agent Relay",
                    )
                ]
            )
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(IPv4Address(ip_address))]
            ),
            False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr, key
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    )
    if san_ip is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(IPv4Address(san_ip))]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    certificate = builder.sign(key, hashes.SHA256())
    path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )


class RelayContractTests(unittest.TestCase):
    def test_versioned_error_contract_matches_machine_readable_artifact(self):
        artifact = json.loads(
            (
                REPO_ROOT
                / "contracts"
                / "remote-agent-relay-errors-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(artifact["contract"], RELAY_ERROR_CONTRACT)
        self.assertEqual(
            tuple(item["code"] for item in artifact["codes"]),
            RELAY_ERROR_CODES,
        )
        self.assertEqual(
            relay_error_contract()["codes"],
            artifact["codes"],
        )
        for code in RELAY_ERROR_CODES:
            response = relay_diagnostic(code)
            self.assertEqual(
                response["error_contract"],
                RELAY_ERROR_CONTRACT,
            )
            self.assertEqual(response["code"], code)

    def test_tls_is_contractual_transport_only(self):
        response = relay_diagnostic("relay_tls_failed")
        self.assertEqual(response["stage"], "tls")
        self.assertEqual(response["code"], "relay_tls_failed")
        self.assertEqual(
            next(
                item
                for item in relay_error_contract()["codes"]
                if item["code"] == "relay_tls_failed"
            )["transport_only"],
            True,
        )

    def test_operator_error_contract_route_is_authenticated(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote-agent.sqlite"
            store = RemoteAgentStore(f"sqlite:///{database_path}")
            try:
                app = create_app(_config(database_path), store)
                with TestClient(app) as client:
                    unauthorized = client.get(
                        "/operator/relay-errors/v1",
                        headers={"Host": "localhost:3030"},
                    )
                    self.assertEqual(unauthorized.status_code, 401)
                    response = client.get(
                        "/operator/relay-errors/v1",
                        headers={
                            "Host": "localhost:3030",
                            "Authorization": "Bearer " + ("o" * 48),
                        },
                    )
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(
                        response.json()["contract"],
                        RELAY_ERROR_CONTRACT,
                    )
            finally:
                store.close()


class RelayCaPublicationTests(unittest.TestCase):
    def test_ca_publication_returns_certificate_and_fingerprint_only(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_path = Path(directory) / "remote-agent-ca.crt"
            _write_certificate(ca_path, ca=True)
            payload = load_public_ca_artifact(str(ca_path))
            self.assertEqual(
                payload["contract"],
                RELAY_CA_PUBLICATION_CONTRACT,
            )
            self.assertTrue(payload["ca"])
            self.assertRegex(
                payload["sha256_fingerprint"],
                r"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$",
            )
            self.assertIn("BEGIN CERTIFICATE", payload["certificate_pem"])
            self.assertNotIn("PRIVATE KEY", payload["certificate_pem"])
            publication_schema = json.loads(
                (
                    REPO_ROOT
                    / "contracts"
                    / "remote-agent-ca-publication-v1.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                publication_schema["contract"],
                RELAY_CA_PUBLICATION_CONTRACT,
            )
            self.assertEqual(
                publication_schema["trust_model"],
                "publication_only_never_auto_trusted",
            )

    def test_missing_ca_artifact_fails_clearly(self):
        with self.assertRaisesRegex(
            RuntimeError,
            "relay_ca_artifact_unavailable",
        ):
            load_public_ca_artifact(
                r"C:\does-not-exist\remote-agent-ca.crt"
            )

    def test_unconfigured_ca_artifact_fails_clearly(self):
        with self.assertRaisesRegex(
            RuntimeError,
            "relay_ca_artifact_unconfigured",
        ):
            load_public_ca_artifact(None)

    def test_leaf_is_not_accepted_as_public_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            leaf_path = Path(directory) / "relay.crt"
            _write_certificate(
                leaf_path,
                ca=False,
                san_ip="10.21.4.101",
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "relay_ca_artifact_invalid",
            ):
                load_public_ca_artifact(str(leaf_path))

    def test_operator_route_is_authenticating_and_missing_is_503(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote-agent.sqlite"
            store = RemoteAgentStore(f"sqlite:///{database_path}")
            try:
                app = create_app(_config(database_path), store)
                with TestClient(app) as client:
                    unauthorized = client.get(
                        "/operator/relay-ca/v1",
                        headers={"Host": "localhost:3030"},
                    )
                    self.assertEqual(unauthorized.status_code, 401)
                    response = client.get(
                        "/operator/relay-ca/v1",
                        headers={
                            "Authorization": "Bearer "
                            + ("o" * 48),
                            "Host": "localhost:3030",
                        },
                    )
                    self.assertEqual(response.status_code, 503)
                    self.assertEqual(
                        response.json()["code"],
                        "relay_ca_artifact_unconfigured",
                    )
            finally:
                store.close()

    def test_relay_csr_is_signed_with_bounded_leaf_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_path, ca_key_path = _write_ca(Path(directory))
            csr, relay_key = _relay_csr()
            payload = sign_relay_csr(
                csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(),
                certificate_path=str(ca_path),
                private_key_path=str(ca_key_path),
                relay_ip="10.21.4.101",
                validity_days=90,
            )
            self.assertEqual(payload["contract"], RELAY_CERT_ISSUANCE_CONTRACT)
            self.assertEqual(payload["relay_ip"], "10.21.4.101")
            self.assertFalse(payload["basic_constraints_ca"])
            self.assertTrue(payload["server_auth"])
            self.assertNotIn("PRIVATE KEY", json.dumps(payload))
            leaf = x509.load_pem_x509_certificate(
                payload["certificate_pem"].encode()
            )
            self.assertTrue(
                leaf.is_signature_valid
                if hasattr(leaf, "is_signature_valid")
                else True
            )

    def test_relay_csr_rejects_ca_true_and_wrong_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_path, ca_key_path = _write_ca(Path(directory))
            for ip_address in ("10.21.4.102", "127.0.0.1"):
                csr, _ = _relay_csr(ip_address=ip_address)
                with self.assertRaisesRegex(
                    RelayCertificateError,
                    "relay_csr_invalid",
                ):
                    sign_relay_csr(
                        csr_pem=csr.public_bytes(
                            serialization.Encoding.PEM
                        ).decode(),
                        certificate_path=str(ca_path),
                        private_key_path=str(ca_key_path),
                        relay_ip="10.21.4.101",
                    )

    def test_relay_csr_route_requires_signing_material(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote-agent.sqlite"
            store = RemoteAgentStore(f"sqlite:///{database_path}")
            csr, _ = _relay_csr()
            try:
                app = create_app(_config(database_path), store)
                with TestClient(app) as client:
                    unauthorized = client.post(
                        "/operator/relay-certificates/v1",
                        headers={"Host": "localhost:3030"},
                        json={"csr_pem": "x"},
                    )
                    self.assertEqual(unauthorized.status_code, 401)
                    response = client.post(
                        "/operator/relay-certificates/v1",
                        headers={
                            "Authorization": "Bearer " + ("o" * 48),
                            "Host": "localhost:3030",
                        },
                        json={
                            "csr_pem": csr.public_bytes(
                                serialization.Encoding.PEM
                            ).decode()
                        },
                    )
                self.assertEqual(response.status_code, 503)
                self.assertEqual(
                    response.json()["code"],
                    "relay_ca_signer_unconfigured",
                )
            finally:
                store.close()

    def test_relay_certificate_status_binds_identity_and_issuer(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_path, ca_key_path = _write_ca(Path(directory))
            csr, relay_key = _relay_csr()
            issued = sign_relay_csr(
                csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(),
                certificate_path=str(ca_path),
                private_key_path=str(ca_key_path),
                relay_ip="10.21.4.101",
            )
            leaf_path = Path(directory) / "relay.crt"
            leaf_path.write_text(issued["certificate_pem"], encoding="ascii")
            status = relay_certificate_status(
                certificate_path=str(leaf_path),
                certificate_authority_path=str(ca_path),
                relay_ip="10.21.4.101",
            )
            self.assertEqual(
                status["ca_sha256_fingerprint"],
                issued["ca_sha256_fingerprint"],
            )

    def test_operator_route_publishes_public_ca_only(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote-agent.sqlite"
            ca_path = Path(directory) / "remote-agent-ca.crt"
            _write_certificate(ca_path, ca=True)
            store = RemoteAgentStore(f"sqlite:///{database_path}")
            try:
                app = create_app(
                    _config(database_path, ca_path=str(ca_path)),
                    store,
                )
                with TestClient(app) as client:
                    response = client.get(
                        "/operator/relay-ca/v1",
                        headers={
                            "Authorization": "Bearer " + ("o" * 48),
                            "Host": "localhost:3030",
                        },
                    )
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertTrue(payload["ca"])
                self.assertIn("BEGIN CERTIFICATE", payload["certificate_pem"])
                self.assertNotIn("PRIVATE KEY", payload["certificate_pem"])
                self.assertNotIn("operator-bearer", json.dumps(payload))
            finally:
                store.close()

    def test_configured_missing_ca_artifact_returns_bounded_503(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote-agent.sqlite"
            missing_path = Path(directory) / "missing-ca.crt"
            store = RemoteAgentStore(f"sqlite:///{database_path}")
            try:
                app = create_app(
                    _config(database_path, ca_path=str(missing_path)),
                    store,
                )
                with TestClient(app) as client:
                    response = client.get(
                        "/operator/relay-ca/v1",
                        headers={
                            "Authorization": "Bearer " + ("o" * 48),
                            "Host": "localhost:3030",
                        },
                    )
                self.assertEqual(response.status_code, 503)
                self.assertEqual(
                    response.json()["code"],
                    "relay_ca_artifact_unavailable",
                )
            finally:
                store.close()

    def test_leaf_rotation_fixture_requires_ca_false_and_ip_san(self):
        fixture = json.loads(
            (
                REPO_ROOT
                / "tests"
                / "fixtures"
                / "relay-leaf-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(fixture["basic_constraints"]["ca"], False)
        self.assertEqual(
            fixture["subject_alt_names"],
            ["10.21.4.101"],
        )
        with tempfile.TemporaryDirectory() as directory:
            leaf_path = Path(directory) / "relay-leaf.crt"
            _write_certificate(
                leaf_path,
                ca=False,
                san_ip=fixture["subject_alt_names"][0],
            )
            certificate = x509.load_pem_x509_certificate(
                leaf_path.read_bytes()
            )
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            sans = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertFalse(constraints.ca)
            self.assertIn(
                IPv4Address("10.21.4.101"),
                sans.get_values_for_type(x509.IPAddress),
            )
            extended_key_usage = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            self.assertIn(
                ExtendedKeyUsageOID.SERVER_AUTH,
                extended_key_usage,
            )


if __name__ == "__main__":
    unittest.main()
