"""Adapters for the `pqcrypto` package (if installed).

Supported families (depending on installed pqcrypto version):
- KEM: ML-KEM / Kyber variants
- Signatures: ML-DSA / Dilithium, Falcon, SPHINCS+
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib

from ..base import AlgorithmSpec


@dataclass(slots=True)
class PqcryptoKEM:
    spec: AlgorithmSpec
    _mod: object

    def keypair(self) -> tuple[bytes, bytes]:
        return self._mod.generate_keypair()

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        ct, ss = self._mod.encrypt(public_key)
        return ct, ss

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return self._mod.decrypt(secret_key, ciphertext)


@dataclass(slots=True)
class PqcryptoSignature:
    spec: AlgorithmSpec
    _mod: object

    def keypair(self) -> tuple[bytes, bytes]:
        return self._mod.generate_keypair()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return self._mod.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            self._mod.verify(signature, message, public_key)
            return True
        except ValueError:
            return False


def _load_first(paths: list[str]) -> object | None:
    for path in paths:
        try:
            return importlib.import_module(path)
        except ModuleNotFoundError:
            continue
    return None


def discover_kems() -> dict[str, PqcryptoKEM]:
    candidates: dict[str, list[str]] = {
        "ml_kem_512": ["pqcrypto.kem.ml_kem_512", "pqcrypto.kem.kyber512"],
        "ml_kem_768": ["pqcrypto.kem.ml_kem_768", "pqcrypto.kem.kyber768"],
        "ml_kem_1024": ["pqcrypto.kem.ml_kem_1024", "pqcrypto.kem.kyber1024"],
    }
    out: dict[str, PqcryptoKEM] = {}
    for name, paths in candidates.items():
        mod = _load_first(paths)
        if mod:
            out[name] = PqcryptoKEM(AlgorithmSpec(name=name, family="kem", backend="pqcrypto"), mod)
    return out


def discover_signatures() -> dict[str, PqcryptoSignature]:
    candidates: dict[str, list[str]] = {
        "ml_dsa_44": ["pqcrypto.sign.ml_dsa_44", "pqcrypto.sign.dilithium2"],
        "ml_dsa_65": ["pqcrypto.sign.ml_dsa_65", "pqcrypto.sign.dilithium3"],
        "ml_dsa_87": ["pqcrypto.sign.ml_dsa_87", "pqcrypto.sign.dilithium5"],
        "falcon_512": ["pqcrypto.sign.falcon_512", "pqcrypto.sign.falcon512"],
        "falcon_1024": ["pqcrypto.sign.falcon_1024", "pqcrypto.sign.falcon1024"],
        "sphincs_sha2_128f_simple": [
            "pqcrypto.sign.sphincs_sha2_128f_simple",
            "pqcrypto.sign.sphincs_shake_128f_simple",
        ],
    }
    out: dict[str, PqcryptoSignature] = {}
    for name, paths in candidates.items():
        mod = _load_first(paths)
        if mod:
            out[name] = PqcryptoSignature(AlgorithmSpec(name=name, family="signature", backend="pqcrypto"), mod)
    return out
