"""High-level cryptographic operation helpers for self-test workflows."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import socket
import subprocess
import sys
import time

from qr_tls.pq import PQRegistry
from qr_tls.tools.cert_lifecycle import CertBundle


@dataclass(slots=True)
class CheckResult:
    name: str
    status: str  # PASS/FAIL/SKIP
    detail: str


class CryptoOperationSuite:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    @staticmethod
    def _wait_for_server_ready(host: str, port: int, proc: subprocess.Popen[str], timeout_s: float = 5.0) -> bool:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if proc.poll() is not None:
                return False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.25)
                if sock.connect_ex((host, port)) == 0:
                    return True
            time.sleep(0.05)
        return False

    @staticmethod
    def _find_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def tls_mutual_auth_roundtrip(self, bundle: CertBundle, port: int | None = None) -> CheckResult:
        if port is None:
            port = self._find_free_port()

        server_cmd = [
            sys.executable,
            "python_tls13/server.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--cert",
            str(bundle.server_cert),
            "--key",
            str(bundle.server_key),
            "--cafile",
            str(bundle.ca_cert),
            "--require-client-cert",
        ]
        client_cmd = [
            sys.executable,
            "python_tls13/client.py",
            "--host",
            "localhost",
            "--port",
            str(port),
            "--cafile",
            str(bundle.ca_cert),
            "--cert",
            str(bundle.client_cert),
            "--key",
            str(bundle.client_key),
            "--message",
            "selftest_ping",
        ]

        proc = subprocess.Popen(server_cmd, cwd=self.repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not self._wait_for_server_ready("127.0.0.1", port, proc):
                stderr = proc.stderr.read().strip() if proc.stderr is not None else ""
                return CheckResult("tls_mutual_auth_roundtrip", "FAIL", stderr or "server failed to become ready")

            run = subprocess.run(client_cmd, cwd=self.repo_root, capture_output=True, text=True, check=True)
            if "TLSv1.3" not in run.stdout or "selftest_ping" not in run.stdout:
                return CheckResult("tls_mutual_auth_roundtrip", "FAIL", f"unexpected output: {run.stdout.strip()}")
            return CheckResult("tls_mutual_auth_roundtrip", "PASS", "TLSv1.3 mutual TLS handshake and echo succeeded")
        except subprocess.CalledProcessError as exc:
            return CheckResult("tls_mutual_auth_roundtrip", "FAIL", exc.stderr.strip() or exc.stdout.strip())
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=3)

    def pq_kem_tests(self, registry: PQRegistry) -> list[CheckResult]:
        if not registry.kems:
            return [CheckResult("pq_kem", "SKIP", "no PQ KEM backend detected")]

        results: list[CheckResult] = []
        for name, kem in registry.kems.items():
            try:
                public_key, secret_key = kem.keypair()
                ciphertext, ss1 = kem.encapsulate(public_key)
                ss2 = kem.decapsulate(secret_key, ciphertext)
                ok = ss1 == ss2
                results.append(CheckResult(f"pq_kem:{name}", "PASS" if ok else "FAIL", "shared secret matched" if ok else "shared secret mismatch"))
            except Exception as exc:
                results.append(CheckResult(f"pq_kem:{name}", "FAIL", str(exc)))
        return results

    def pq_signature_tests(self, registry: PQRegistry) -> list[CheckResult]:
        if not registry.signatures:
            return [CheckResult("pq_signature", "SKIP", "no PQ signature backend detected")]

        results: list[CheckResult] = []
        msg = b"quantum-resistant tls selftest"
        for name, sig in registry.signatures.items():
            try:
                public_key, secret_key = sig.keypair()
                signature = sig.sign(secret_key, msg)
                ok = sig.verify(public_key, msg, signature)
                results.append(CheckResult(f"pq_sig:{name}", "PASS" if ok else "FAIL", "verify true" if ok else "verify false"))
            except Exception as exc:
                results.append(CheckResult(f"pq_sig:{name}", "FAIL", str(exc)))
        return results
