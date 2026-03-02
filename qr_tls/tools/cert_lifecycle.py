"""Certificate lifecycle management helpers based on OpenSSL CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import re
import subprocess

_ALLOWED_DN = re.compile(r"^[A-Za-z0-9._-]+$")
_ALLOWED_SAN = re.compile(r"^[A-Za-z0-9._\-:,*]+$")


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

    def _validate_dn_value(self, value: str, field: str) -> None:
        if not _ALLOWED_DN.fullmatch(value):
            raise ValueError(f"invalid {field}: only [A-Za-z0-9._-] allowed")

    def _validate_san_value(self, value: str) -> None:
        if not _ALLOWED_SAN.fullmatch(value):
            raise ValueError("invalid san: only [A-Za-z0-9._-:,*] allowed")

    def _run(self, *cmd: str) -> None:
        try:
            subprocess.run(cmd, cwd=self.workdir, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            stdout = (exc.stdout or "").strip()
            detail = stderr or stdout or str(exc)
            raise CertificateLifecycleError(f"command failed: {' '.join(cmd)}\n{detail}") from exc

    def initialize_ca(self, cn: str = "QR_TLS_Test_Root_CA") -> tuple[Path, Path]:
        self._validate_dn_value(cn, "cn")
        ca_key = self.workdir / "ca.key"
        ca_cert = self.workdir / "ca.crt"
        self._run(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-sha256",
            "-days",
            "365",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-subj",
            f"/CN={cn}",
        )
        os.chmod(ca_key, 0o600)
        return ca_key, ca_cert

    def issue_leaf(self, name: str, san: str, ca_key: Path, ca_cert: Path) -> tuple[Path, Path, Path]:
        self._validate_dn_value(name, "name")
        self._validate_san_value(san)

        key = self.workdir / f"{name}.key"
        csr = self.workdir / f"{name}.csr"
        cert = self.workdir / f"{name}.crt"
        extfile = self.workdir / f"{name}.ext"
        extfile.write_text(
            "\n".join(
                [
                    "basicConstraints=CA:FALSE",
                    "keyUsage = digitalSignature, keyEncipherment",
                    "extendedKeyUsage = serverAuth, clientAuth",
                    f"subjectAltName = {san}",
                ]
            ),
            encoding="utf-8",
        )

        self._run(
            "openssl",
            "req",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={name}",
        )
        self._run(
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "180",
            "-sha256",
            "-extfile",
            str(extfile),
        )
        os.chmod(key, 0o600)
        extfile.unlink(missing_ok=True)
        return key, csr, cert

    def verify_certificate(self, cert: Path, ca_cert: Path) -> None:
        self._run("openssl", "verify", "-CAfile", str(ca_cert), str(cert))

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
