"""Standalone toy cryptographic primitives (no OpenSSL/ssl/hashlib dependency)."""

from __future__ import annotations


def hash32(data: bytes) -> bytes:
    """Return a deterministic 32-byte digest using a simple ARX-style mixer."""
    state = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89]
    for i, b in enumerate(data):
        idx = i & 7
        x = state[idx]
        x ^= (b + i) & 0xFF
        x = ((x << 5) | (x >> 27)) & 0xFFFFFFFF
        x = (x + state[(idx - 1) & 7] + (0x9E3779B9 ^ i)) & 0xFFFFFFFF
        state[idx] = x
    out = bytearray()
    for x in state:
        out.extend(x.to_bytes(4, "big"))
    return bytes(out)


def _mac(key: bytes, message: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = hash32(key)
    key = key.ljust(block, b"\x00")
    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5C) for x in key)
    inner = hash32(ipad + message)
    return hash32(opad + inner)


def sign_message(secret_key: bytes, message: bytes) -> bytes:
    return _mac(secret_key, message)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    return _mac(public_key, message) == signature
