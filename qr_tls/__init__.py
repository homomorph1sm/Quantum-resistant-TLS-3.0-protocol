"""Quantum-ready TLS toolkit.

This package extracts TLS helpers from Python's ssl module so they can be
extended with custom algorithm transitions in future iterations.
"""

from .ssl_tools import TLSClientConfig, TLSServerConfig, build_client_context, build_server_context

__all__ = [
    "TLSClientConfig",
    "TLSServerConfig",
    "build_client_context",
    "build_server_context",
]
