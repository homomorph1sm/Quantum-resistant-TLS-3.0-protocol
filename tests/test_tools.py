from pathlib import Path

from qr_tls.tools.cert_lifecycle import CertificateLifecycleManager


def test_certificate_lifecycle_bundle(tmp_path: Path) -> None:
    mgr = CertificateLifecycleManager(tmp_path)
    bundle = mgr.create_bundle()
    assert bundle.ca_cert.exists()
    assert bundle.server_cert.exists()
    assert bundle.client_cert.exists()
