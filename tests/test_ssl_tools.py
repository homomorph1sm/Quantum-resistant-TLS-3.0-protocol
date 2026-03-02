import ssl

from qr_tls.ssl_tools import TLSClientConfig, TLSServerConfig, build_client_context


def test_build_client_context_tls13() -> None:
    ctx = build_client_context(TLSClientConfig(insecure=True))
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3


def test_server_config_defaults() -> None:
    cfg = TLSServerConfig(certfile="a", keyfile="b")
    assert cfg.require_client_cert is False
    assert cfg.minimum_version == ssl.TLSVersion.TLSv1_3
