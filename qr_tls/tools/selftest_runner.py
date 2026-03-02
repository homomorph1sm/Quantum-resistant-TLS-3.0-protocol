"""Unified self-test runner for certificate lifecycle and crypto operations."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory

from qr_tls.pq import PQRegistry
from qr_tls.tools.cert_lifecycle import CertificateLifecycleError, CertificateLifecycleManager
from qr_tls.tools.crypto_ops import CheckResult, CryptoOperationSuite


class UnifiedSelfTestRunner:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def run(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        with TemporaryDirectory(prefix="qr_tls_selftest_") as tmp:
            cert_mgr = CertificateLifecycleManager(Path(tmp))
            try:
                bundle = cert_mgr.create_bundle()
                results.append(CheckResult("cert_lifecycle", "PASS", f"issued certs in {tmp}"))
            except CertificateLifecycleError as exc:
                results.append(CheckResult("cert_lifecycle", "FAIL", str(exc)))
                return results

            suite = CryptoOperationSuite(self.repo_root)
            results.append(suite.tls_mutual_auth_roundtrip(bundle))

            registry = PQRegistry.autodiscover()
            results.extend(suite.pq_kem_tests(registry))
            results.extend(suite.pq_signature_tests(registry))
        return results

    @staticmethod
    def as_jsonable(results: list[CheckResult]) -> list[dict[str, str]]:
        return [asdict(item) for item in results]
