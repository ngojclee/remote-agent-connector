from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


RELAY_CERT_ISSUANCE_CONTRACT = (
    "business-mcp-remote-agent-relay-certificate-v1"
)
MAX_CSR_BYTES = 32 * 1024
MIN_LEAF_VALIDITY_DAYS = 1
MAX_LEAF_VALIDITY_DAYS = 397


class RelayCertificateError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(code)
        self.code = code
        self.message = message


def _fingerprint_sha256(value: bytes) -> str:
    return ":".join(
        f"{byte:02X}" for byte in hashlib.sha256(value).digest()
    )


def _iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _signing_hash(private_key: Any) -> hashes.HashAlgorithm | None:
    if isinstance(
        private_key,
        (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
    ):
        return None
    return hashes.SHA256()


def _public_bytes(public_key: Any) -> bytes:
    if isinstance(
        public_key,
        (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey),
    ):
        return public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_certificate(path: str | None) -> x509.Certificate:
    if not path:
        raise RelayCertificateError(
            "relay_ca_signer_unconfigured",
            "Relay CA certificate is not configured.",
        )
    try:
        return x509.load_pem_x509_certificate(Path(path).read_bytes())
    except (OSError, ValueError, TypeError):
        raise RelayCertificateError(
            "relay_ca_signer_unavailable",
            "Relay CA certificate is not available.",
        ) from None


def _load_private_key(path: str | None) -> Any:
    if not path:
        raise RelayCertificateError(
            "relay_ca_signer_unconfigured",
            "Relay CA private key is not configured.",
        )
    try:
        return serialization.load_pem_private_key(
            Path(path).read_bytes(),
            password=None,
        )
    except (OSError, ValueError, TypeError):
        raise RelayCertificateError(
            "relay_ca_signer_unavailable",
            "Relay CA private key is not available.",
        ) from None


def load_signing_material(
    *,
    certificate_path: str | None,
    private_key_path: str | None,
    now: datetime | None = None,
) -> tuple[x509.Certificate, Any]:
    """Load and pair a CA-only certificate with its signing key."""
    certificate = _load_certificate(certificate_path)
    private_key = _load_private_key(private_key_path)
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        key_usage = certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound:
        raise RelayCertificateError(
            "relay_ca_signer_invalid",
            "Relay CA signer material is invalid.",
        ) from None
    current = now or datetime.now(timezone.utc)
    if (
        not constraints.ca
        or not key_usage.key_cert_sign
        or current < certificate.not_valid_before_utc
        or current >= certificate.not_valid_after_utc
        or _public_bytes(certificate.public_key())
        != _public_bytes(private_key.public_key())
    ):
        raise RelayCertificateError(
            "relay_ca_signer_invalid",
            "Relay CA signer material is invalid.",
        )
    return certificate, private_key


def _certificate_metadata(certificate: x509.Certificate) -> dict[str, Any]:
    return {
        "certificate_pem": certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii"),
        "sha256_fingerprint": _fingerprint_sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_before": _iso_time(certificate.not_valid_before_utc),
        "not_after": _iso_time(certificate.not_valid_after_utc),
    }


def relay_certificate_status(
    *,
    certificate_path: str,
    certificate_authority_path: str,
    relay_ip: str,
) -> dict[str, Any]:
    """Describe a relay leaf without exposing its private key or contents."""
    try:
        leaf = x509.load_pem_x509_certificate(
            Path(certificate_path).read_bytes()
        )
        authority = _load_certificate(certificate_authority_path)
    except (OSError, ValueError, TypeError) as exc:
        raise RelayCertificateError(
            "relay_certificate_unavailable",
            "Relay certificate is not available.",
        ) from exc
    try:
        constraints = leaf.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        names = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.IPAddress)
        eku = leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        raise RelayCertificateError(
            "relay_certificate_invalid",
            "Relay certificate is invalid.",
        ) from None
    if (
        constraints.ca
        or names != [ipaddress.ip_address(relay_ip)]
        or ExtendedKeyUsageOID.SERVER_AUTH not in eku
        or leaf.issuer != authority.subject
    ):
        raise RelayCertificateError(
            "relay_certificate_invalid",
            "Relay certificate is invalid.",
        )
    return {
        **_certificate_metadata(leaf),
        "relay_ip": relay_ip,
        "ca_sha256_fingerprint": _fingerprint_sha256(
            authority.public_bytes(serialization.Encoding.DER)
        ),
        "basic_constraints_ca": False,
        "server_auth": True,
    }


def sign_relay_csr(
    *,
    csr_pem: str,
    certificate_path: str | None,
    private_key_path: str | None,
    relay_ip: str,
    validity_days: int = 90,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate a relay CSR and issue a short-lived server-only leaf."""
    if not MIN_LEAF_VALIDITY_DAYS <= validity_days <= MAX_LEAF_VALIDITY_DAYS:
        raise RelayCertificateError(
            "relay_certificate_validity_invalid",
            "Relay certificate validity is outside the accepted range.",
        )
    encoded = csr_pem.strip()
    if (
        not encoded
        or len(encoded.encode("utf-8")) > MAX_CSR_BYTES
        or encoded.count("-----BEGIN CERTIFICATE REQUEST-----") != 1
        or "PRIVATE KEY" in encoded
    ):
        raise RelayCertificateError(
            "relay_csr_invalid",
            "Relay certificate request is invalid.",
        )
    try:
        csr = x509.load_pem_x509_csr(encoded.encode("ascii"))
    except (ValueError, TypeError, UnicodeError):
        raise RelayCertificateError(
            "relay_csr_invalid",
            "Relay certificate request is invalid.",
        ) from None
    if not csr.is_signature_valid:
        raise RelayCertificateError(
            "relay_csr_invalid",
            "Relay certificate request signature is invalid.",
        )
    try:
        requested_ip = ipaddress.ip_address(relay_ip)
    except ValueError:
        raise RelayCertificateError(
            "relay_certificate_target_invalid",
            "Relay address is invalid.",
        ) from None
    try:
        names = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.IPAddress)
        constraints = csr.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        eku = csr.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        raise RelayCertificateError(
            "relay_csr_invalid",
            "Relay certificate request extensions are incomplete.",
        ) from None
    if (
        names != [requested_ip]
        or constraints.ca
        or ExtendedKeyUsageOID.SERVER_AUTH not in eku
        or ExtendedKeyUsageOID.CLIENT_AUTH in eku
    ):
        raise RelayCertificateError(
            "relay_csr_invalid",
            "Relay certificate request identity or usage is invalid.",
        )
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < 2048:
        raise RelayCertificateError(
            "relay_csr_invalid",
            "Relay certificate request key is too weak.",
        )
    if isinstance(public_key, ec.EllipticCurvePublicKey) and (
        public_key.curve.key_size < 256
    ):
        raise RelayCertificateError(
            "relay_csr_invalid",
            "Relay certificate request key is too weak.",
        )

    authority, signing_key = load_signing_material(
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        now=now,
    )
    current = now or datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(authority.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(requested_ip)]),
            critical=False,
        )
    )
    try:
        certificate = builder.sign(signing_key, _signing_hash(signing_key))
    except (ValueError, TypeError):
        raise RelayCertificateError(
            "relay_certificate_signing_failed",
            "Relay certificate could not be signed.",
        ) from None
    return {
        "contract": RELAY_CERT_ISSUANCE_CONTRACT,
        "relay_ip": relay_ip,
        "validity_days": validity_days,
        "ca_sha256_fingerprint": _fingerprint_sha256(
            authority.public_bytes(serialization.Encoding.DER)
        ),
        "basic_constraints_ca": False,
        "server_auth": True,
        **_certificate_metadata(certificate),
    }
