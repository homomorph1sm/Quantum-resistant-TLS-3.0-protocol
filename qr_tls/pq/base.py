"""Interfaces for post-quantum algorithms."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class AlgorithmSpec:
    name: str
    family: str
    backend: str


class KEMAlgorithm(Protocol):
    spec: AlgorithmSpec

    def keypair(self) -> tuple[bytes, bytes]: ...
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]: ...
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes: ...


class SignatureAlgorithm(Protocol):
    spec: AlgorithmSpec

    def keypair(self) -> tuple[bytes, bytes]: ...
    def sign(self, secret_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
