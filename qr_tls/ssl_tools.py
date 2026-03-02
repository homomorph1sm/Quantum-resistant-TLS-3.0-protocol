"""Reusable TLS helpers built on top of Python's stdlib ssl module."""

from __future__ import annotations

from dataclasses import dataclass
import ssl


@dataclass(slots=True)
class TLSServerConfig:
    certfile: str
    keyfile: str
    cafile: str | None = None
    require_client_cert: bool = False
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    maximum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3


@dataclass(slots=True)
class TLSClientConfig:
    cafile: str | None = None
    certfile: str | None = None
    keyfile: str | None = None
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    maximum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3


def build_server_context(config: TLSServerConfig) -> ssl.SSLContext:
    if config.require_client_cert and not config.cafile:
        raise ValueError("cafile is required when require_client_cert=True")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = config.minimum_version
    context.maximum_version = config.maximum_version
    context.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)

    if config.cafile:
        context.load_verify_locations(cafile=config.cafile)

    if config.require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
    elif config.cafile:
        context.verify_mode = ssl.CERT_OPTIONAL
    else:
        context.verify_mode = ssl.CERT_NONE

    context.options |= ssl.OP_NO_COMPRESSION
    return context


def build_client_context(config: TLSClientConfig) -> ssl.SSLContext:
    if (config.certfile is None) ^ (config.keyfile is None):
        raise ValueError("certfile and keyfile must be provided together")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=config.cafile)

    if config.certfile and config.keyfile:
        context.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)

    context.minimum_version = config.minimum_version
    context.maximum_version = config.maximum_version
    context.options |= ssl.OP_NO_COMPRESSION
    return context
