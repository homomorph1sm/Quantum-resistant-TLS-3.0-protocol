import ssl

from qr_tls.ssl_tools import TLSClientConfig, TLSServerConfig, build_client_context, build_server_context


def test_build_client_context_tls13() -> None:
    ctx = build_client_context(TLSClientConfig(insecure=True))
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_server_config_defaults() -> None:
    cfg = TLSServerConfig(certfile="a", keyfile="b")
    assert cfg.require_client_cert is False
    assert cfg.minimum_version == ssl.TLSVersion.TLSv1_3


def test_server_with_cafile_uses_cert_optional(monkeypatch) -> None:
    class DummyContext:
        def __init__(self, protocol: int) -> None:
            self.protocol = protocol
            self.verify_mode = None
            self.options = 0

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:
            pass

        def load_verify_locations(self, cafile: str) -> None:
            pass

    monkeypatch.setattr(ssl, "SSLContext", DummyContext)
    ctx = build_server_context(TLSServerConfig(certfile="c", keyfile="k", cafile="ca.pem", require_client_cert=False))
    assert ctx.verify_mode == ssl.CERT_OPTIONAL
