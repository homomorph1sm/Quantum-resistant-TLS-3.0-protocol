#!/usr/bin/env python3
<<<<<<< codex/add-python-implementation-of-tls-3.0-ruoswh
"""Simple TLS 1.3 client using extracted qr_tls ssl helpers."""
=======
"""Simple TLS 1.3 client using Python's standard ssl module."""
>>>>>>> main

from __future__ import annotations

import argparse
<<<<<<< codex/add-python-implementation-of-tls-3.0-ruoswh
import os
import socket
import stat
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from qr_tls.ssl_tools import TLSClientConfig, build_client_context


def validate_private_key_permissions(key_path: str) -> None:
    st_mode = os.stat(key_path).st_mode
    perms = stat.S_IMODE(st_mode)
    if perms not in (0o400, 0o600):
        raise PermissionError(f"Insecure private key permissions for {key_path}: {oct(perms)}. Expected 0o400 or 0o600.")


def run(host: str, port: int, cafile: str | None, certfile: str | None, keyfile: str | None, message: str) -> None:
    if keyfile:
        validate_private_key_permissions(keyfile)
    context = build_client_context(TLSClientConfig(cafile=cafile, certfile=certfile, keyfile=keyfile))
=======
import socket
import ssl


def build_client_context(cafile: str | None, insecure: bool, certfile: str | None = None, keyfile: str | None = None) -> ssl.SSLContext:
    """Create a strict TLS 1.3 client context."""
    if insecure:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)

    if certfile:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    return context


<<<<<<< HEAD
def run(
    host: str,
    port: int,
    cafile: str | None,
    insecure: bool,
    message: str,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> None:
    context = build_client_context(cafile, insecure, certfile=certfile, keyfile=keyfile)
=======
def run(host: str, port: int, cafile: str | None, insecure: bool, message: str) -> None:
    context = build_client_context(cafile, insecure)
>>>>>>> main
>>>>>>> f41133bcd80b955439cf4d0709cb5820f3636ff1

    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            tls_sock.sendall(message.encode("utf-8"))
            data = tls_sock.recv(4096)
            print(f"[*] Connected with TLS version: {tls_sock.version()}")
            print(f"[*] Cipher suite: {tls_sock.cipher()}")
            print(data.decode("utf-8", errors="replace"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Python TLS 1.3 echo client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cafile", help="CA file used to verify server certificate")
<<<<<<< HEAD
    parser.add_argument("--cert", help="Client certificate PEM file")
    parser.add_argument("--key", help="Client private key PEM file")
=======
<<<<<<< codex/add-python-implementation-of-tls-3.0-ruoswh
    parser.add_argument("--cert", help="Client certificate PEM file (for mTLS)")
    parser.add_argument("--key", help="Client private key PEM file (for mTLS)")
=======
>>>>>>> f41133bcd80b955439cf4d0709cb5820f3636ff1
    parser.add_argument("--insecure", action="store_true", help="Disable certificate verification")
>>>>>>> main
    parser.add_argument("--message", default="hello from python tls1.3 client")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
<<<<<<< HEAD
    run(args.host, args.port, args.cafile, args.insecure, args.message, args.cert, args.key)
=======
<<<<<<< codex/add-python-implementation-of-tls-3.0-ruoswh
    run(args.host, args.port, args.cafile, args.cert, args.key, args.message)
=======
    run(args.host, args.port, args.cafile, args.insecure, args.message)
>>>>>>> main
>>>>>>> f41133bcd80b955439cf4d0709cb5820f3636ff1
