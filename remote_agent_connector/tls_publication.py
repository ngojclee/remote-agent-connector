from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


RELAY_CA_PUBLICATION_CONTRACT = (
    "business-mcp-remote-agent-ca-publication-v1"
)
MAX_PUBLIC_CA_ARTIFACT_BYTES = 128 * 1024


class RelayCaArtifactError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(code)
        self.code = code
        self.message = message


def _fingerprint_sha256(value: bytes) -> str:
    digest = hashlib.sha256(value).digest()
    return ":".join(f"{byte:02X}" for byte in digest)


def load_public_ca_artifact(
    path: str | None,
) -> dict[str, Any]:
    """Load a CA certificate for publication, never for trust decisions."""
    if not path:
        raise RelayCaArtifactError(
            "relay_ca_artifact_unconfigured",
            "Relay CA publication is not configured.",
        )
    artifact = Path(path)
    try:
        raw = artifact.read_bytes()
    except (OSError, ValueError):
        raise RelayCaArtifactError(
            "relay_ca_artifact_unavailable",
            "Relay CA certificate is not available.",
        ) from None
    if (
        len(raw) > MAX_PUBLIC_CA_ARTIFACT_BYTES
        or raw.count(b"-----BEGIN CERTIFICATE-----") != 1
        or b"PRIVATE KEY" in raw
    ):
        raise RelayCaArtifactError(
            "relay_ca_artifact_invalid",
            "Relay CA certificate artifact is invalid.",
        )
    try:
        certificate = x509.load_pem_x509_certificate(raw)
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except (ValueError, x509.ExtensionNotFound):
        raise RelayCaArtifactError(
            "relay_ca_artifact_invalid",
            "Relay CA certificate artifact is invalid.",
        ) from None
    canonical_pem = certificate.public_bytes(Encoding.PEM)
    if (
        raw.replace(b"\r\n", b"\n").strip()
        != canonical_pem.replace(b"\r\n", b"\n").strip()
    ):
        raise RelayCaArtifactError(
            "relay_ca_artifact_invalid",
            "Relay CA certificate artifact is invalid.",
        )
    if not constraints.ca:
        raise RelayCaArtifactError(
            "relay_ca_artifact_invalid",
            "Relay CA certificate artifact is invalid.",
        )
    der = certificate.public_bytes(Encoding.DER)
    pem = certificate.public_bytes(Encoding.PEM).decode("ascii")
    return {
        "contract": RELAY_CA_PUBLICATION_CONTRACT,
        "certificate_pem": pem,
        "sha256_fingerprint": _fingerprint_sha256(der),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_before": certificate.not_valid_before_utc.isoformat(),
        "not_after": certificate.not_valid_after_utc.isoformat(),
        "ca": True,
    }
