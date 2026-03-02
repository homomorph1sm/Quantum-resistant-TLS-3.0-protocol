"""Certificate lifecycle helpers without OpenSSL CLI dependency.

This module creates *project-local* certificate artifacts for testing workflows.
Artifacts are JSON payloads wrapped in PEM-like markers and signed with a
standalone MAC primitive, so no OpenSSL command invocation is required.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import os
from pathlib import Path
import re
import secrets

from qr_tls.crypto.simple_crypto import sign_message, verify_signature

_ALLOWED_DN = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")
_SAN_ITEM = re.compile(r"^(DNS:[A-Za-z0-9*._-]{1,253}|IP:(?:\d{1,3}\.){3}\d{1,3})$")


@dataclass(slots=True)
class CertBundle:
    ca_key: Path
    ca_cert: Path
    server_key: Path
    server_csr: Path
    server_cert: Path
    client_key: Path
    client_csr: Path
    client_cert: Path


class CertificateLifecycleError(RuntimeError):
    """Raised when certificate lifecycle operations fail."""


class CertificateLifecycleManager:
    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._fixtures = Path(__file__).with_name("testdata")

    @staticmethod
    def _validate_cn(value: str) -> None:
        if not _ALLOWED_DN.fullmatch(value) or "/" in value or "\n" in value or "\r" in value:
            raise ValueError(f"Unsafe CN value: {value!r}")

    @staticmethod
    def _validate_san(value: str) -> None:
        if "\n" in value or "\r" in value:
            raise ValueError(f"Unsafe SAN value: {value!r}")
        items = [part.strip() for part in value.split(",") if part.strip()]
        if not items or any(not _SAN_ITEM.fullmatch(item) for item in items):
            raise ValueError(f"Unsafe SAN value: {value!r}")

    @staticmethod
    def _write_private_key(path: Path) -> str:
        key_material = secrets.token_hex(32)
        path.write_text(key_material, encoding="utf-8")
        os.chmod(path, 0o600)
        return key_material

    @staticmethod
    def _write_pem_json(path: Path, marker: str, payload: dict[str, str]) -> None:
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        b64 = base64.b64encode(blob).decode("ascii")
        path.write_text(f"-----BEGIN {marker}-----\n{b64}\n-----END {marker}-----\n", encoding="utf-8")

    @staticmethod
    def _read_pem_json(path: Path, marker: str) -> dict[str, str]:
        text = path.read_text(encoding="utf-8").strip().splitlines()
        if len(text) < 3 or text[0] != f"-----BEGIN {marker}-----" or text[-1] != f"-----END {marker}-----":
            raise CertificateLifecycleError(f"invalid {marker} format: {path}")
        data = base64.b64decode("".join(text[1:-1]).encode("ascii"))
        return json.loads(data.decode("utf-8"))

    def initialize_ca(self, cn: str = "QR TLS Test Root CA") -> tuple[Path, Path]:
        self._validate_cn(cn)
        ca_key = self.workdir / "ca.key"
        ca_cert = self.workdir / "ca.crt"
        key = self._write_private_key(ca_key)
        payload = {"subject": cn, "issuer": cn, "serial": secrets.token_hex(8)}
        payload["sig"] = sign_message(key.encode("utf-8"), json.dumps(payload, sort_keys=True).encode("utf-8")).hex()
        self._write_pem_json(ca_cert, "QR TLS CERT", payload)
        return ca_key, ca_cert

    def issue_leaf(self, name: str, san: str, ca_key: Path, ca_cert: Path) -> tuple[Path, Path, Path]:
        self._validate_cn(name)
        self._validate_san(san)

        key = self.workdir / f"{name}.key"
        csr = self.workdir / f"{name}.csr"
        cert = self.workdir / f"{name}.crt"

        leaf_key = self._write_private_key(key)
        csr_payload = {"subject": name, "san": san, "public_hint": leaf_key[:24]}
        self._write_pem_json(csr, "QR TLS CSR", csr_payload)

        ca_key_material = ca_key.read_text(encoding="utf-8").strip()
        ca_payload = self._read_pem_json(ca_cert, "QR TLS CERT")
        cert_payload = {
            "subject": name,
            "issuer": str(ca_payload["subject"]),
            "san": san,
            "serial": secrets.token_hex(8),
        }
        cert_payload["sig"] = sign_message(
            ca_key_material.encode("utf-8"), json.dumps(cert_payload, sort_keys=True).encode("utf-8")
        ).hex()
        self._write_pem_json(cert, "QR TLS CERT", cert_payload)
        return key, csr, cert

    def verify_certificate(self, cert: Path, ca_cert: Path) -> None:
        cert_payload = self._read_pem_json(cert, "QR TLS CERT")
        ca_payload = self._read_pem_json(ca_cert, "QR TLS CERT")
        signed = {k: v for k, v in cert_payload.items() if k != "sig"}
        ca_key_material = (self.workdir / "ca.key").read_text(encoding="utf-8").strip()

        if cert_payload.get("issuer") != ca_payload.get("subject"):
            raise CertificateLifecycleError("issuer mismatch")
        sig = bytes.fromhex(str(cert_payload["sig"]))
        ok = verify_signature(ca_key_material.encode("utf-8"), json.dumps(signed, sort_keys=True).encode("utf-8"), sig)
        if not ok:
            raise CertificateLifecycleError(f"certificate verification failed: {cert}")

    def create_bundle(self) -> CertBundle:
        ca_key, ca_cert = self.initialize_ca()
        server_key, server_csr, server_cert = self.issue_leaf("localhost", "DNS:localhost,IP:127.0.0.1", ca_key, ca_cert)
        client_key, client_csr, client_cert = self.issue_leaf("client", "DNS:client", ca_key, ca_cert)

        self.verify_certificate(server_cert, ca_cert)
        self.verify_certificate(client_cert, ca_cert)

        return CertBundle(
            ca_key=ca_key,
            ca_cert=ca_cert,
            server_key=server_key,
            server_csr=server_csr,
            server_cert=server_cert,
            client_key=client_key,
            client_csr=client_csr,
            client_cert=client_cert,
        )
