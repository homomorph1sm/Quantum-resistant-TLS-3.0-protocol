"""Algorithm registry for post-quantum crypto backends."""

from __future__ import annotations

from dataclasses import dataclass, field

from .adapters import oqs_adapter, pqcrypto_adapter


@dataclass
class PQRegistry:
    kems: dict[str, object] = field(default_factory=dict)
    signatures: dict[str, object] = field(default_factory=dict)

    @classmethod
    def autodiscover(cls) -> "PQRegistry":
        kems: dict[str, object] = {}
        signatures: dict[str, object] = {}

        for discover in (pqcrypto_adapter.discover_kems, oqs_adapter.discover_kems):
            kems.update(discover())
        for discover in (pqcrypto_adapter.discover_signatures, oqs_adapter.discover_signatures):
            signatures.update(discover())

        return cls(kems=kems, signatures=signatures)

    def summary(self) -> dict[str, list[str]]:
        return {
            "kems": sorted(self.kems.keys()),
            "signatures": sorted(self.signatures.keys()),
        }
