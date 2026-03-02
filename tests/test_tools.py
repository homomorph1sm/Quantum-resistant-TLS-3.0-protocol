from pathlib import Path

import pytest

from qr_tls.tools.cert_lifecycle import CertificateLifecycleError, CertificateLifecycleManager


def test_certificate_lifecycle_bundle(tmp_path: Path) -> None:
    mgr = CertificateLifecycleManager(tmp_path)
    bundle = mgr.create_bundle()
    assert bundle.ca_cert.exists()
    assert bundle.server_cert.exists()
    assert bundle.client_cert.exists()


def test_reject_invalid_dn_and_san(tmp_path: Path) -> None:
    mgr = CertificateLifecycleManager(tmp_path)
    ca_key, ca_cert = mgr.initialize_ca()

    with pytest.raises(ValueError):
        mgr.initialize_ca("bad/cn")
    with pytest.raises(ValueError):
        mgr.issue_leaf("localhost", "DNS:ok\nbasicConstraints=CA:TRUE", ca_key, ca_cert)


def test_run_propagates_stderr(tmp_path: Path) -> None:
    mgr = CertificateLifecycleManager(tmp_path)
    with pytest.raises(CertificateLifecycleError):
        mgr._run("unknown-subcommand")


def test_selftest_runner_reports_cert_failure(monkeypatch, tmp_path: Path) -> None:
    from qr_tls.tools.selftest_runner import UnifiedSelfTestRunner

    def boom(self):
        raise CertificateLifecycleError("openssl missing")

    monkeypatch.setattr(CertificateLifecycleManager, "create_bundle", boom)
    results = UnifiedSelfTestRunner(tmp_path).run()
    assert results[0].name == "cert_lifecycle"
    assert results[0].status == "FAIL"
    assert "openssl missing" in results[0].detail
