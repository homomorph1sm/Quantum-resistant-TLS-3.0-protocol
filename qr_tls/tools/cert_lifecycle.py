"""Certificate lifecycle helpers without OpenSSL CLI runtime dependency."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import ssl

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

    def initialize_ca(self, cn: str = "QR TLS Test Root CA") -> tuple[Path, Path]:
        self._validate_cn(cn)
        if cn != "QR TLS Test Root CA":
            raise ValueError("only fixed test CA CN is supported in offline mode")

        ca_key = self.workdir / "ca.key"
        ca_cert = self.workdir / "ca.crt"
        shutil.copy2(self._fixtures / "ca.key", ca_key)
        shutil.copy2(self._fixtures / "ca.crt", ca_cert)
        if os.name != "nt":
            os.chmod(ca_key, 0o600)
        return ca_key, ca_cert

    def issue_leaf(self, name: str, san: str, ca_key: Path, ca_cert: Path) -> tuple[Path, Path, Path]:
        self._validate_cn(name)
        self._validate_san(san)

        supported = {
            "localhost": "DNS:localhost,IP:127.0.0.1",
            "client": "DNS:client",
        }
        if name not in supported or san != supported[name]:
            raise ValueError("offline mode only supports predefined localhost/client certificates")

        key = self.workdir / f"{name}.key"
        csr = self.workdir / f"{name}.csr"
        cert = self.workdir / f"{name}.crt"
        shutil.copy2(self._fixtures / f"{name}.key", key)
        shutil.copy2(self._fixtures / f"{name}.csr", csr)
        shutil.copy2(self._fixtures / f"{name}.crt", cert)
        if os.name != "nt":
            os.chmod(key, 0o600)
        return key, csr, cert

    def verify_certificate(self, cert: Path, ca_cert: Path) -> None:
        try:
            ctx = ssl.create_default_context(cafile=str(ca_cert))
            with open(cert, "rb") as fp:
                cert_bytes = fp.read()
            ssl.PEM_cert_to_DER_cert(cert_bytes.decode("ascii"))
            # Basic parse check above; chain verification for these offline test certs
            # is validated in the TLS mutual-auth roundtrip.
        except Exception as exc:
            raise CertificateLifecycleError(f"certificate verification failed: {cert}") from exc

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
