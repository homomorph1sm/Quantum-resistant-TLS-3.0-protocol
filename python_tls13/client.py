#!/usr/bin/env python3
"""Simple TLS 1.3 client using extracted qr_tls ssl helpers."""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from qr_tls.ssl_tools import TLSClientConfig, build_client_context


def run(host: str, port: int, cafile: str | None, certfile: str | None, keyfile: str | None, insecure: bool, message: str) -> None:
    context = build_client_context(TLSClientConfig(cafile=cafile, certfile=certfile, keyfile=keyfile, insecure=insecure))

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
    parser.add_argument("--cert", help="Client certificate PEM file (for mTLS)")
    parser.add_argument("--key", help="Client private key PEM file (for mTLS)")
    parser.add_argument("--insecure", action="store_true", help="Disable certificate verification")
    parser.add_argument("--message", default="hello from python tls1.3 client")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args.host, args.port, args.cafile, args.cert, args.key, args.insecure, args.message)
