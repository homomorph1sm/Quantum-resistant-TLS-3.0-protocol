#!/usr/bin/env python3
"""Simple TLS 1.3 client using Python's standard ssl module."""

from __future__ import annotations

import argparse
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
    parser.add_argument("--cert", help="Client certificate PEM file")
    parser.add_argument("--key", help="Client private key PEM file")
    parser.add_argument("--insecure", action="store_true", help="Disable certificate verification")
    parser.add_argument("--message", default="hello from python tls1.3 client")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args.host, args.port, args.cafile, args.insecure, args.message, args.cert, args.key)
