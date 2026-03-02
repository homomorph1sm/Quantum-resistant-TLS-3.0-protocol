# Copilot Instructions

## Project Overview

A Python TLS 1.3 reference implementation layered with an optional post-quantum (PQ) cryptography façade. The project has two distinct layers:

- **`python_tls13/`** — Standalone TLS 1.3 echo server/client using Python's stdlib `ssl`. Entry points for manual testing.
- **`qr_tls/`** — Reusable library providing TLS context factories (`ssl_tools.py`), a PQ algorithm registry (`pq/`), certificate lifecycle management (`tools/cert_lifecycle.py`), and a unified self-test runner (`tools/selftest_runner.py`).

## Architecture: Key Data Flows

1. **TLS context creation**: callers instantiate `TLSServerConfig` / `TLSClientConfig` dataclasses → pass to `build_server_context()` / `build_client_context()` → receive a ready `ssl.SSLContext`.
2. **PQ algorithm discovery**: `PQRegistry.autodiscover()` probes two optional backends (`pqcrypto_adapter`, `oqs_adapter`) and returns a `PQRegistry(kems={...}, signatures={...})`. Keys are `snake_case` algorithm names (e.g. `ml_kem_768`).
3. **PQ operation pattern**: every algorithm object satisfies either `KEMAlgorithm` or `SignatureAlgorithm` Protocol (defined in `qr_tls/pq/base.py`). Always carry an `AlgorithmSpec(name, family, backend)`.
4. **Self-test pipeline**: `selftest.py` → `UnifiedSelfTestRunner.run()` → issues ephemeral certs via `CertificateLifecycleManager` (wraps OpenSSL CLI) → spawns server subprocess → runs client subprocess → collects `CheckResult(name, status, detail)` list.

## Critical Developer Workflows

```bash
# Run the full self-test suite (requires openssl on PATH)
python selftest.py

# Run unit tests
pytest tests/

# Manual TLS roundtrip (generate cert first — see python_tls13/certs/README.md)
python python_tls13/server.py --host 127.0.0.1 --port 8443 --cert <crt> --key <key>
python python_tls13/client.py --host 127.0.0.1 --port 8443 --cafile <crt> --message "hello"
```

PQ backends are **optional**: tests and self-test gracefully `SKIP` when neither `oqs` (liboqs) nor `pqcrypto` is installed.

## Project-Specific Conventions

- **Result type**: all self-test checks return `CheckResult(name, status, detail)` where `status` is `"PASS"` / `"FAIL"` / `"SKIP"`. Never raise exceptions from test methods; catch and return `FAIL`.
- **Algorithm naming**: registry keys use `snake_case` with `-` → `_` and `+` → `plus` (e.g. `sphincs_sha2_128f_simple`). `AlgorithmSpec.name` retains the original canonical name (e.g. `"SPHINCS+-SHA2-128f-simple"`).
- **Adding a new PQ backend**: create a new adapter module in `qr_tls/pq/adapters/` implementing `discover_kems() -> dict` and `discover_signatures() -> dict`, then import and wire both functions into `PQRegistry.autodiscover()` in `registry.py`.
- **TLS enforcement**: both `minimum_version` and `maximum_version` are always pinned to `TLSv1_3`. Do not relax these defaults.
- **Certificate issuance**: `CertificateLifecycleManager` invokes the system `openssl` binary via `subprocess`. All `_run()` calls use `check=True`; failures raise `CalledProcessError`.

## Security Constraints to Preserve

- `insecure=True` / `ssl._create_unverified_context()` exists in both `ssl_tools.py` and `python_tls13/client.py` — this is a known risk; do not expand its usage or add new call sites.
- `CN` and `SAN` arguments passed to `CertificateLifecycleManager.issue_leaf()` and `initialize_ca()` are written directly into OpenSSL config/CLI — always validate/sanitize these inputs before passing user-controlled data.
- When `cafile` is provided to `build_server_context()`, set `require_client_cert=True` explicitly; passing `cafile` alone does **not** enable verification (`verify_mode` stays `CERT_NONE` by default).

## Key Files

| File | Purpose |
|------|---------|
| `qr_tls/ssl_tools.py` | TLS context factory — primary integration point |
| `qr_tls/pq/base.py` | `KEMAlgorithm` / `SignatureAlgorithm` Protocols + `AlgorithmSpec` |
| `qr_tls/pq/registry.py` | `PQRegistry` — algorithm registry and autodiscovery |
| `qr_tls/pq/adapters/oqs_adapter.py` | liboqs backend |
| `qr_tls/pq/adapters/pqcrypto_adapter.py` | pqcrypto backend |
| `qr_tls/tools/cert_lifecycle.py` | Ephemeral PKI via OpenSSL CLI |
| `qr_tls/tools/crypto_ops.py` | `CryptoOperationSuite` — KEM/signature/TLS roundtrip checks |
| `qr_tls/tools/selftest_runner.py` | `UnifiedSelfTestRunner` — orchestrates the full test pipeline |
| `selftest.py` | CLI entrypoint; exits non-zero on any `FAIL` |
