"""Adapters for python-oqs/liboqs (if installed)."""

from __future__ import annotations

from dataclasses import dataclass

from ..base import AlgorithmSpec


@dataclass(slots=True)
class OqsKEM:
    spec: AlgorithmSpec

    def keypair(self) -> tuple[bytes, bytes]:
        import oqs

        kem = oqs.KeyEncapsulation(self.spec.name)
        try:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key
        finally:
            del kem

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        import oqs

        kem = oqs.KeyEncapsulation(self.spec.name)
        try:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret
        finally:
            del kem

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        import oqs

        kem = oqs.KeyEncapsulation(self.spec.name, secret_key=secret_key)
        try:
            return kem.decap_secret(ciphertext)
        finally:
            del kem


@dataclass(slots=True)
class OqsSignature:
    spec: AlgorithmSpec

    def keypair(self) -> tuple[bytes, bytes]:
        import oqs

        sig = oqs.Signature(self.spec.name)
        try:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            return public_key, secret_key
        finally:
            del sig

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        import oqs

        sig = oqs.Signature(self.spec.name, secret_key=secret_key)
        try:
            return sig.sign(message)
        finally:
            del sig

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        import oqs

        verifier = oqs.Signature(self.spec.name)
        try:
            return verifier.verify(message, signature, public_key)
        finally:
            del verifier


def discover_kems() -> dict[str, OqsKEM]:
    try:
        import oqs
    except ModuleNotFoundError:
        return {}

    supported = set(oqs.get_enabled_kem_mechanisms())
    preferred = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "Kyber512",
        "Kyber768",
        "Kyber1024",
    ]
    return {
        name.lower().replace("-", "_"): OqsKEM(AlgorithmSpec(name=name, family="kem", backend="oqs"))
        for name in preferred
        if name in supported
    }


def discover_signatures() -> dict[str, OqsSignature]:
    try:
        import oqs
    except ModuleNotFoundError:
        return {}

    supported = set(oqs.get_enabled_sig_mechanisms())
    preferred = [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "Dilithium2",
        "Dilithium3",
        "Dilithium5",
        "Falcon-512",
        "Falcon-1024",
        "SPHINCS+-SHA2-128f-simple",
    ]
    return {
        name.lower().replace("+", "plus").replace("-", "_"): OqsSignature(
            AlgorithmSpec(name=name, family="signature", backend="oqs")
        )
        for name in preferred
        if name in supported
    }
