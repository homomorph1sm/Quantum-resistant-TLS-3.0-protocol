# Quantum-resistant-TLS-3.0-protocol

> 注意：当前并不存在正式的 TLS 3.0 标准，主流是 TLS 1.3。

本仓库包含：

1. `python_tls13/`：TLS 1.3 client/server 示例。
2. `qr_tls/ssl_tools.py`：可复用 TLS 上下文构建工具。
3. `qr_tls/tools/` + `selftest.py`：统一自测（证书流程、TLS联调、PQ算法探测）。
4. `qr_tls/crypto/simple_crypto.py`：独立实现的轻量密码学原语（不依赖 OpenSSL CLI）。

## 快速开始

```bash
python3 selftest.py
```

## 说明

- 证书生命周期工具 `CertificateLifecycleManager` 已移除对 `openssl` 命令行的依赖，改为项目内可验证的测试证书格式。
- TLS 示例仍基于 Python `ssl`（TLS 1.3）进行网络握手演示。
