# Quantum-resistant-TLS-3.0-protocol

> 注意：IETF 当前并没有正式发布 TLS 3.0 标准；生产环境主流仍然是 TLS 1.3。

本仓库当前提供三层能力：

1. `python_tls13/`：可直接运行的 TLS 1.3 client/server 示例。
2. `qr_tls/ssl_tools.py`：可复用 SSL/TLS 工具层（后续便于做算法替换）。
3. `qr_tls/tools/` + `selftest.py`：统一自测工具，覆盖证书生命周期、TLS利用、加解密与签名验签测试。

## 快速开始：TLS 1.3

### 1) 生成本地证书

```bash
mkdir -p python_tls13/certs
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
  -keyout python_tls13/certs/server.key \
  -out python_tls13/certs/server.crt \
  -subj "/CN=localhost"
```

### 2) 启动服务端

```bash
python3 python_tls13/server.py \
  --host 127.0.0.1 \
  --port 8443 \
  --cert python_tls13/certs/server.crt \
  --key python_tls13/certs/server.key
```

### 3) 启动客户端

```bash
python3 python_tls13/client.py \
  --host localhost \
  --port 8443 \
  --cafile python_tls13/certs/server.crt \
  --message "hello over tls1.3"
```

> 若要做双向认证(mTLS)，客户端可额外传入 `--cert` 和 `--key`。私钥权限需为 `0400` 或 `0600`。

> `--insecure` 仅用于测试，会显式禁用证书与主机名校验，严禁在生产环境使用。

## 抽取后的 SSL 工具（供二次开发）

```python
from qr_tls.ssl_tools import TLSServerConfig, TLSClientConfig, build_server_context, build_client_context

server_ctx = build_server_context(TLSServerConfig(certfile="server.crt", keyfile="server.key"))
client_ctx = build_client_context(TLSClientConfig(cafile="ca.crt", certfile="client.crt", keyfile="client.key"))
```

## 抗量子算法（SOTA）适配

统一注册入口：`qr_tls.pq.PQRegistry`。

- KEM: ML-KEM (Kyber)
- Signature: ML-DSA (Dilithium), Falcon, SPHINCS+
- 后端自动发现：`pqcrypto`、`python-oqs` (`oqs`)

```python
from qr_tls.pq import PQRegistry

registry = PQRegistry.autodiscover()
print(registry.summary())
```

## 统一自测脚本

运行：

```bash
python3 selftest.py
```

自测内容：

- CA -> 叶子证书签发 -> 证书链验证（全生命周期关键步骤）
- 使用签发证书进行 TLS1.3 双向认证联调
- 对当前可用的 PQ KEM 执行 keypair/encapsulate/decapsulate
- 对当前可用的 PQ Signature 执行 keypair/sign/verify

并输出人类可读报告 + JSON 结果。

## 可选依赖

```bash
pip install pqcrypto oqs
```
