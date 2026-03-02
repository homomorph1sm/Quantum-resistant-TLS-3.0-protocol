from qr_tls.pq import PQRegistry


def test_registry_autodiscover_returns_summary_shape() -> None:
    registry = PQRegistry.autodiscover()
    summary = registry.summary()
    assert set(summary.keys()) == {"kems", "signatures"}
    assert isinstance(summary["kems"], list)
    assert isinstance(summary["signatures"], list)
