#!/usr/bin/env python3
"""Simple TLS 1.3 echo server using extracted qr_tls ssl helpers."""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ssl
from typing import Tuple

from qr_tls.ssl_tools import TLSServerConfig, build_server_context


def handle_client(conn: ssl.SSLSocket, addr: Tuple[str, int]) -> None:
    data = conn.recv(4096)
    if not data:
        return

    response = f"[tls_version={conn.version()} cipher={conn.cipher()[0]}] ".encode("utf-8") + data
    conn.sendall(response)
    print(f"[+] {addr} => {data!r}")


def serve(host: str, port: int, certfile: str, keyfile: str, cafile: str | None, require_client_cert: bool) -> None:
    context = build_server_context(
        TLSServerConfig(
            certfile=certfile,
            keyfile=keyfile,
            cafile=cafile,
            require_client_cert=require_client_cert,
        )
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[*] TLS1.3 server listening on {host}:{port}")

        while True:
            client, addr = sock.accept()
            try:
                with context.wrap_socket(client, server_side=True) as tls_conn:
                    handle_client(tls_conn, addr)
            except ssl.SSLError as exc:
                print(f"[!] TLS error from {addr}: {exc}")
            finally:
                client.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Python TLS 1.3 echo server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", required=True, help="Server certificate PEM file")
    parser.add_argument("--key", required=True, help="Server private key PEM file")
    parser.add_argument("--cafile", help="CA file for client cert verification (optional)")
    parser.add_argument("--require-client-cert", action="store_true", help="Require and verify client certificates")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    serve(args.host, args.port, args.cert, args.key, args.cafile, args.require_client_cert)
