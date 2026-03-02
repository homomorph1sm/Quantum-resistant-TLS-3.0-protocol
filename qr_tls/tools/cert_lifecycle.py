"""Certificate lifecycle management helpers based on OpenSSL CLI."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess


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


class CertificateLifecycleManager:
    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)

    def _ensure_openssl_config(self) -> Path:
        config_path = self.workdir / "openssl.cnf"
        if config_path.exists():
            return config_path

        config_path.write_text(
            "\n".join(
                [
                    "[ req ]",
                    "distinguished_name = req_distinguished_name",
                    "prompt = no",
                    "[ req_distinguished_name ]",
                    "CN = qr_tls_local",
                ]
            ),
            encoding="utf-8",
        )
        return config_path

    def _run(self, *cmd: str) -> None:
        env = os.environ.copy()
        conf = env.get("OPENSSL_CONF")
        if not conf or not Path(conf).exists():
            env["OPENSSL_CONF"] = str(self._ensure_openssl_config())
        subprocess.run(cmd, cwd=self.workdir, check=True, capture_output=True, text=True, env=env)

    def initialize_ca(self, cn: str = "QR TLS Test Root CA") -> tuple[Path, Path]:
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
        return ca_key, ca_cert

    def issue_leaf(self, name: str, san: str, ca_key: Path, ca_cert: Path) -> tuple[Path, Path, Path]:
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
