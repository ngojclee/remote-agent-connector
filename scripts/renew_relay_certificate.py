#!/usr/bin/env python3
"""Renew the Remote Agent relay leaf through the Business MCP Hub CA signer.

Runs on the relay host. It never holds the CA private key: it generates a new
leaf key locally, sends only the CSR to the Hub, verifies the returned leaf
against the published CA, then swaps the files and reloads the relay. Any
failure after the swap restores the previous pair.

Schedule it from cron or a systemd timer, for example daily. The script is a
no-op until the leaf is inside the renewal window.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_HUB_URL = "http://127.0.0.1:8790"
DEFAULT_TLS_DIR = "/home/Docker/business-mcp-hub/remote-agent/tls"
DEFAULT_CA_CERT = "/home/Docker/business-mcp-hub/remote-agent/ca/remote-agent-ca.crt"
DEFAULT_RELAY_IP = "10.21.4.101"
DEFAULT_RELAY_PORT = 3051
DEFAULT_CONTAINER = "remote-agent-wss-relay"
DEFAULT_RENEW_BEFORE_DAYS = 30
DEFAULT_VALIDITY_DAYS = 90


class RenewalError(RuntimeError):
    pass


def run(command: list[str], *, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(
        command,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or b"").decode(errors="replace").strip()
        raise RenewalError(f"{command[0]} failed: {detail[:400]}")
    return result.stdout


def parse_openssl_time(value: str) -> datetime:
    # openssl prints "Dec 12 22:53:29 2028 GMT"
    return datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def leaf_not_after(path: Path) -> datetime | None:
    if not path.is_file():
        return None
    raw = run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"])
    match = re.search(rb"notAfter=(.+)", raw)
    if not match:
        raise RenewalError("could not read the current relay certificate expiry")
    return parse_openssl_time(match.group(1).decode())


def make_csr(work: Path, relay_ip: str, common_name: str) -> tuple[Path, str]:
    key_path = work / "relay.key"
    run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            str(key_path),
        ]
    )
    os.chmod(key_path, 0o600)
    config = work / "relay-san.cnf"
    config.write_text(
        "\n".join(
            [
                "[req]",
                "distinguished_name = req_distinguished_name",
                "req_extensions = req_ext",
                "prompt = no",
                "",
                "[req_distinguished_name]",
                f"CN = {common_name}",
                "",
                "[req_ext]",
                "basicConstraints = critical, CA:FALSE",
                "keyUsage = critical, digitalSignature, keyEncipherment",
                "extendedKeyUsage = serverAuth",
                "subjectAltName = @alt_names",
                "",
                "[alt_names]",
                f"IP.1 = {relay_ip}",
                "",
            ]
        ),
        encoding="ascii",
    )
    csr_path = work / "relay.csr"
    run(
        [
            "openssl",
            "req",
            "-new",
            "-sha256",
            "-key",
            str(key_path),
            "-out",
            str(csr_path),
            "-config",
            str(config),
        ]
    )
    return key_path, csr_path.read_text(encoding="ascii")


def request_certificate(hub_url: str, token: str, csr_pem: str) -> dict:
    url = hub_url.rstrip("/") + "/admin/api/remote-agent/relay-certificates"
    payload = json.dumps({"csr_pem": csr_pem}).encode()
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        raise RenewalError(f"Hub refused the CSR ({exc.code}): {detail}") from None
    except urllib.error.URLError as exc:
        raise RenewalError(f"could not reach the Hub: {exc.reason}") from None
    for field in ("certificate_pem", "sha256_fingerprint", "not_after"):
        if field not in body:
            raise RenewalError("Hub response is missing " + field)
    return body


def verify_pair(ca_cert: Path, key_path: Path, cert_path: Path, relay_ip: str) -> None:
    run(["openssl", "verify", "-CAfile", str(ca_cert), str(cert_path)])
    san = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName"])
    if f"IP Address:{relay_ip}".encode() not in san:
        raise RenewalError("issued certificate does not carry the relay IP SAN")
    from_key = run(["openssl", "pkey", "-in", str(key_path), "-pubout"])
    from_cert = run(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"])
    if from_key.strip() != from_cert.strip():
        raise RenewalError("issued certificate does not match the new private key")


def install(tls_dir: Path, key_path: Path, cert_path: Path) -> Path | None:
    """Atomically replace the pair, returning the backup directory."""
    existing_key = tls_dir / "relay.key"
    existing_cert = tls_dir / "relay.crt"
    backup: Path | None = None
    if existing_key.is_file() or existing_cert.is_file():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = tls_dir / f"backup-{stamp}"
        backup.mkdir(mode=0o700, exist_ok=True)
        for source in (existing_key, existing_cert):
            if source.is_file():
                shutil.copy2(source, backup / source.name)
    staging_cert = tls_dir / ".relay.crt.new"
    staging_key = tls_dir / ".relay.key.new"
    shutil.copy2(cert_path, staging_cert)
    shutil.copy2(key_path, staging_key)
    os.chmod(staging_cert, 0o644)
    os.chmod(staging_key, 0o600)
    for uid, gid in ((2999, 2999),):
        try:
            os.chown(staging_key, uid, gid)
            os.chown(staging_cert, uid, gid)
        except (PermissionError, OSError):
            pass
    os.replace(staging_cert, existing_cert)
    os.replace(staging_key, existing_key)
    return backup


def reload_relay(container: str) -> None:
    run(["docker", "exec", container, "nginx", "-t"])
    run(["docker", "exec", container, "nginx", "-s", "reload"])


def restore(backup: Path | None, tls_dir: Path, container: str) -> None:
    if backup is None:
        return
    for name in ("relay.crt", "relay.key"):
        source = backup / name
        if source.is_file():
            shutil.copy2(source, tls_dir / name)
    try:
        reload_relay(container)
    except RenewalError as exc:
        print(f"rollback reload failed: {exc}", file=sys.stderr)


def live_handshake(relay_ip: str, port: int, ca_cert: Path) -> None:
    result = subprocess.run(
        [
            "openssl",
            "s_client",
            "-connect",
            f"{relay_ip}:{port}",
            "-CAfile",
            str(ca_cert),
            "-verify_return_error",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    text = result.stdout.decode(errors="replace")
    if "Verify return code: 0 (ok)" not in text:
        tail = text.strip().splitlines()[-3:] if text.strip() else ["no output"]
        raise RenewalError("post-renewal TLS check failed: " + " ".join(tail))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub-url", default=os.getenv("BUSINESS_MCP_HUB_URL", DEFAULT_HUB_URL))
    parser.add_argument("--tls-dir", default=os.getenv("REMOTE_AGENT_TLS_DIR", DEFAULT_TLS_DIR))
    parser.add_argument("--ca-cert", default=os.getenv("REMOTE_AGENT_CA_CERT", DEFAULT_CA_CERT))
    parser.add_argument("--relay-ip", default=os.getenv("REMOTE_AGENT_RELAY_IP", DEFAULT_RELAY_IP))
    parser.add_argument("--relay-port", type=int, default=int(os.getenv("REMOTE_AGENT_RELAY_PORT", DEFAULT_RELAY_PORT)))
    parser.add_argument("--container", default=os.getenv("REMOTE_AGENT_RELAY_CONTAINER", DEFAULT_CONTAINER))
    parser.add_argument(
        "--renew-before-days",
        type=int,
        default=int(os.getenv("REMOTE_AGENT_RENEW_BEFORE_DAYS", DEFAULT_RENEW_BEFORE_DAYS)),
    )
    parser.add_argument("--force", action="store_true", help="renew even when the leaf is fresh")
    args = parser.parse_args()

    token = os.getenv("BUSINESS_MCP_ADMIN_TOKEN", "").strip()
    if not token:
        raise RenewalError("BUSINESS_MCP_ADMIN_TOKEN is required")
    tls_dir = Path(args.tls_dir)
    ca_cert = Path(args.ca_cert)
    if not tls_dir.is_dir():
        raise RenewalError(f"tls dir not found: {tls_dir}")
    if not ca_cert.is_file():
        raise RenewalError(f"CA certificate not found: {ca_cert}")

    current_expiry = leaf_not_after(tls_dir / "relay.crt")
    now = datetime.now(timezone.utc)
    if (
        current_expiry is not None
        and not args.force
        and current_expiry - now > timedelta(days=args.renew_before_days)
    ):
        print(
            json.dumps(
                {
                    "action": "skipped",
                    "reason": "inside_validity_window",
                    "not_after": current_expiry.isoformat(),
                    "renew_before_days": args.renew_before_days,
                }
            )
        )
        return 0

    with tempfile.TemporaryDirectory(prefix="relay-renew-") as temp_dir:
        work = Path(temp_dir)
        key_path, csr_pem = make_csr(work, args.relay_ip, f"AGY2API Remote Agent Relay {args.relay_ip}")
        issued = request_certificate(args.hub_url, token, csr_pem)
        cert_path = work / "relay.crt"
        cert_path.write_text(issued["certificate_pem"], encoding="ascii")
        verify_pair(ca_cert, key_path, cert_path, args.relay_ip)
        backup = install(tls_dir, key_path, cert_path)
        try:
            reload_relay(args.container)
            live_handshake(args.relay_ip, args.relay_port, ca_cert)
        except RenewalError as exc:
            restore(backup, tls_dir, args.container)
            raise
        print(
            json.dumps(
                {
                    "action": "renewed",
                    "relay_ip": args.relay_ip,
                    "leaf_fingerprint": issued["sha256_fingerprint"],
                    "not_after": issued["not_after"],
                    "ca_fingerprint": issued.get("ca_sha256_fingerprint"),
                    "backup": str(backup) if backup else None,
                }
            )
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RenewalError as exc:
        print(f"relay renewal failed: {exc}", file=sys.stderr)
        sys.exit(1)
