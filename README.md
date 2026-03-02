# Quantum-resistant-TLS-3.0-protocol


这个仓库新增了一个可运行的 Python TLS 1.3 参考实现（客户端 + 服务端），用于：

1. 验证 Python 是否可以实现主流 TLS 协议；
2. 作为未来接入“后量子/混合密钥交换”实验的基础骨架。

## 目录结构

- `python_tls13/server.py`：TLS 1.3 Echo Server（支持 mutual TLS 可选）
- `python_tls13/client.py`：TLS 1.3 Echo Client
- `python_tls13/certs/README.md`：本地测试证书生成说明

## 快速开始

### 1) 生成本地自签名证书

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
  --host 127.0.0.1 \
  --port 8443 \
  --cafile python_tls13/certs/server.crt \
  --message "hello over tls1.3"
```

## 关于“Python 版 TLS 3.0”

- 不存在“主流 TLS 3.0”实现，因为 TLS 3.0 不是当前标准。
- Python 有主流 TLS 1.3 实现能力：通过标准库 `ssl`（底层 OpenSSL）即可使用现代密码套件与握手流程。
- 如果你后续希望加入真正的“抗量子”能力，建议方向是：
  - OpenSSL + OQS provider（或 BoringSSL/其他支持 PQ KEM 的栈）；
  - 在 Python 中通过 `ssl`/`ctypes`/外部代理服务接入混合密钥交换。
