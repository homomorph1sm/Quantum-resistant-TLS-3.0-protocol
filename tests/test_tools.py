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


def test_verify_certificate_detects_tampering(tmp_path: Path) -> None:
    mgr = CertificateLifecycleManager(tmp_path)
    ca_key, ca_cert = mgr.initialize_ca()
    _, _, cert = mgr.issue_leaf("localhost", "DNS:localhost", ca_key, ca_cert)
    cert.write_text(cert.read_text(encoding="utf-8") + "tamper", encoding="utf-8")

    with pytest.raises(CertificateLifecycleError):
        mgr.verify_certificate(cert, ca_cert)
