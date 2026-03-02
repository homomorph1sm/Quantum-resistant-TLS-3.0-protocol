# 安全审计报告（高危漏洞）

> 审计日期：2026-03-02  
> 范围：全量代码库（`python_tls13/`、`qr_tls/`、`tests/`、`selftest.py`）  
> 原则：仅收录高危（High）及以上级别漏洞

---

## 漏洞 #1 — 安全控制声明与实现完全脱离（幽灵函数）

**严重级别：** ⛔ 高危  
**CWE：** CWE-636 (Not Failing Securely)  
**受影响文件：**
- `tests/test_cli_security.py`（第 5–6 行）
- `python_tls13/server.py`（全文无此函数）
- `python_tls13/client.py`（全文无此函数）

### 问题描述

`test_cli_security.py` 中引用了两个不存在的函数：

```python
# tests/test_cli_security.py
from python_tls13.client import validate_private_key_permissions as validate_client_key
from python_tls13.server import validate_private_key_permissions as validate_server_key
```

`python_tls13/server.py` 和 `python_tls13/client.py` 中**均没有 `validate_private_key_permissions` 函数**。

**后果：**

1. `pytest tests/` 运行到该文件时直接抛出 `ImportError`，测试套件崩溃或报错，而**私钥权限检查从未被执行**；
2. 开发者和 CI 系统可能误认为私钥权限校验已落地，实际上这是完全的安全空壳（Security Theater）；
3. 若服务器私钥被设置为全局可读（如 `chmod 644`），任何本地用户均可读取它，但代码层面零阻拦。

### 修复建议

在 `python_tls13/server.py` 和 `python_tls13/client.py` 中分别添加如下函数，并在加载私钥前调用它：

```python
import stat
import os

def validate_private_key_permissions(path: str) -> None:
    """拒绝权限过宽的私钥文件（仅允许 0o600 / 0o400）。"""
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o177:  # 除属主读/写外有其他位
        raise PermissionError(
            f"Private key {path!r} has insecure permissions {oct(mode)}. "
            "Expected 0o600 or 0o400."
        )
```

在 `server.py` 的 `serve()` 入口处，`build_server_context()` 之前调用：

```python
validate_private_key_permissions(keyfile)
```

在 `client.py` 的 `run()` 中，当 `certfile` 不为 `None` 时调用：

```python
if certfile:
    validate_private_key_permissions(keyfile)
```

---

## 漏洞 #2 — OpenSSL extfile SAN 字段注入（可伪造 CA 证书）

**严重级别：** ⛔ 高危  
**CWE：** CWE-93 (Improper Neutralization of CRLF Sequences)  
**受影响文件：** `qr_tls/tools/cert_lifecycle.py`（第 55–66 行）

### 问题描述

`san` 参数被直接拼接写入 OpenSSL 扩展配置文件，**没有任何输入验证**：

```python
extfile.write_text(
    "\n".join([
        "basicConstraints=CA:FALSE",
        "keyUsage = digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth, clientAuth",
        f"subjectAltName = {san}",   # ← san 未过滤，直接写入文件
    ]),
    encoding="utf-8",
)
```

若 `san` 包含换行符，攻击者可注入任意 OpenSSL 扩展配置行。

**攻击示例：**

```python
# 调用者传入恶意 san：
san = "DNS:legit.example.com\nbasicConstraints=CA:TRUE"
```

生成的 extfile 内容变为：

```
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:legit.example.com
basicConstraints=CA:TRUE          ← 注入！后出现的配置覆盖前面
```

OpenSSL 按后出现的配置优先，最终颁发的证书带 `CA:TRUE`，成为**伪造的 CA 证书**，可用于签发任意域名的可信证书，**完全破坏 PKI 信任链**。

同理，`cn` 和 `name` 参数在以下位置被直接拼接进 `-subj`，允许 DN 字段注入（`/` 分隔符）：

```python
"-subj", f"/CN={cn}",    # cert_lifecycle.py 第 40 行
"-subj", f"/CN={name}",  # cert_lifecycle.py 第 73 行
```

### 修复建议

在 `CertificateLifecycleManager` 中添加输入验证函数，并在 `initialize_ca()` / `issue_leaf()` 入口处调用：

```python
import re

_SAFE_CN_RE = re.compile(r'^[a-zA-Z0-9_\-. ]{1,64}$')
_SAFE_SAN_RE = re.compile(r'^(DNS:[a-zA-Z0-9_\-.*]+|IP:\d{1,3}(\.\d{1,3}){3})(,(DNS:[a-zA-Z0-9_\-.*]+|IP:\d{1,3}(\.\d{1,3}){3}))*$')

def _validate_cn(value: str) -> None:
    if not _SAFE_CN_RE.match(value):
        raise ValueError(f"Unsafe CN value: {value!r}")

def _validate_san(value: str) -> None:
    if not _SAFE_SAN_RE.match(value):
        raise ValueError(f"Unsafe SAN value: {value!r}")
```

在 `initialize_ca()` 起始处调用 `_validate_cn(cn)`，在 `issue_leaf()` 起始处调用 `_validate_cn(name)` 和 `_validate_san(san)`。

---

## 漏洞 #3 — 完全禁用 TLS 证书验证（MITM 零阻拦）

**严重级别：** ⛔ 高危  
**CWE：** CWE-295 (Improper Certificate Validation)  
**受影响文件：**
- `qr_tls/ssl_tools.py`（第 44–45 行）
- `python_tls13/client.py`（第 11–12 行）

### 问题描述

两处代码均使用 Python 私有 API 完全绕过 TLS 验证：

```python
# qr_tls/ssl_tools.py
if config.insecure:
    context = ssl._create_unverified_context()   # 禁用证书链验证 + 主机名校验

# python_tls13/client.py
if insecure:
    context = ssl._create_unverified_context()
```

**影响：**

1. `ssl._create_unverified_context()` 是 Python 私有 API（前缀 `_`），无稳定性保证；
2. 该调用同时关闭了证书链验证（`verify_mode=CERT_NONE`）**和**主机名验证（`check_hostname=False`），使所有在途 MITM 攻击完全透明；
3. `--insecure` 可由任意命令行用户触发，无需特权。

### 修复建议

若业务确需保留 `insecure` 模式（仅用于受控的本地测试），请改用标准 API 并强制打印警告，防止被静默滥用：

```python
import warnings

if config.insecure:
    warnings.warn(
        "insecure=True disables ALL certificate verification. "
        "NEVER use in production.",
        stacklevel=2,
    )
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
```

如果 `insecure` 模式在生产代码路径中不需要，直接删除该分支。

---

## 漏洞 #4 — 签名验证逻辑可被伪造（双重异常吞噬）

**严重级别：** ⛔ 高危  
**CWE：** CWE-347 (Improper Verification of Cryptographic Signature)  
**受影响文件：** `qr_tls/pq/adapters/pqcrypto_adapter.py`（第 41–50 行）

### 问题描述

```python
def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        self._mod.verify(public_key, message, signature)
        return True
    except Exception:                              # ← 吞噬一切异常
        try:
            self._mod.verify(signature, message, public_key)  # ← 参数顺序颠倒重试
            return True
        except Exception:
            return False
```

**两个独立的高危路径：**

**路径 A — 签名伪造：**  
对于某些 pqcrypto 后端，`verify(signature, message, public_key)` 的参数顺序与正确签名无关，只要第一个参数长度符合公钥格式要求，调用可能不抛出异常而直接返回，导致该函数对**无效签名**返回 `True`（签名伪造）。

**路径 B — 验证结果不可信：**  
任何底层库的内部错误（内存错误、类型错误、缓冲区问题）都会被 `except Exception` 静默吞噬，第二次重试若也出错则返回 `False`，将**合法签名**判定为无效（验证拒绝服务）。

### 修复建议

确认每个 pqcrypto 子模块的实际 API 签名后，固定调用约定，不使用异常控制流：

```python
def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
    # pqcrypto 统一约定：verify(pk, msg, sig)，验证失败抛出 ValueError
    try:
        self._mod.verify(public_key, message, signature)
        return True
    except ValueError:
        return False
    # 其他异常（如 TypeError、内存错误）正常向上传播，不静默吞噬
```

若确实存在需要兼容两种参数顺序的模块，应在 `discover_signatures()` 阶段通过 `getattr` 探测 API 签名并在构造时固化，而不是在每次 `verify()` 调用时盲试。

---

## 漏洞汇总

| # | 严重性 | 受影响文件 | 漏洞摘要 |
|---|--------|-----------|---------|
| 1 | ⛔ 高危 | `tests/test_cli_security.py`<br>`python_tls13/server.py`<br>`python_tls13/client.py` | 私钥权限检查函数不存在，安全控制完全落空 |
| 2 | ⛔ 高危 | `qr_tls/tools/cert_lifecycle.py` | SAN/DN 字段注入，可伪造 CA 证书 |
| 3 | ⛔ 高危 | `qr_tls/ssl_tools.py`<br>`python_tls13/client.py` | 私有 API 完全禁用 TLS 验证，MITM 零阻力 |
| 4 | ⛔ 高危 | `qr_tls/pq/adapters/pqcrypto_adapter.py` | 双重异常吞噬导致签名伪造或合法签名被拒 |
