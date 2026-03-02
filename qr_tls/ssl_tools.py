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
    insecure: bool = False
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    maximum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3


def build_server_context(config: TLSServerConfig) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = config.minimum_version
    context.maximum_version = config.maximum_version
    context.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)

    if config.cafile:
        context.load_verify_locations(cafile=config.cafile)

    context.verify_mode = ssl.CERT_REQUIRED if config.require_client_cert else ssl.CERT_NONE
    context.options |= ssl.OP_NO_COMPRESSION
    return context


def build_client_context(config: TLSClientConfig) -> ssl.SSLContext:
    if config.insecure:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=config.cafile)

    if config.certfile:
        context.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)

    context.minimum_version = config.minimum_version
    context.maximum_version = config.maximum_version
    context.options |= ssl.OP_NO_COMPRESSION
    return context
