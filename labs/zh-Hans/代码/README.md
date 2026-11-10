# torlab — 简体中文教学版 Tor 客户端

Python 包 `torlab` 用于配合《Tor 剖析》的实验，教学性地实现真实 Tor 协议的部分机制。它**仅供私有实验网络**使用，网络说明见 [`../README.md`](../README.md)。它不是完整的 Tor 客户端，也不是可用于保护匿名性的工具。

## 预定测试

在**仓库根目录**运行；需要 Python 3.11+、`pytest` 和 `cryptography`：

```bash
PYTHONPATH=labs/zh-Hans/代码 python3 -m pytest -q labs/zh-Hans/代码/torlab/test
make -C labs/zh-Hans test
```

这些命令针对简体中文环境，而非意大利语目录 `labs/it/codice/torlab/`。单元测试不能证明与公共 Tor 网络互操作，更不能证明匿名性或安全性。

## 包含的模块

| 模块 | 实验 | 用途 |
|---|---:|---|
| `channel.py` | 1 | TLS 通道、初始化信元及中继身份验证 |
| `cells.py` | 2 | 定长与变长信元、转发消息 |
| `ntor.py` | 3 | ntor 与 ntor-v3 密钥协商 |
| `encryption.py`、`circuit.py` | 4 | 分层加密与电路扩展 |
| `stream.py` | 5 | 数据流与 SENDME |
| `directory.py` | 6 | 共识文档、证书及微描述符 |
| `path_selection.py` | 7 | 加权路径选择 |
| `onion.py` | 8 | onion v3 地址与描述符 |
| `pow.py` | 9 | Blake2b 门限检查；Equi-X 解为**模拟数据** |
| `traffic.py` | 12 | 解析已解密的 TLS 流量捕获 |
| `metrics.py` | 15 | 共识统计 |
| `simulation.py` | 19 | 首次受损时间模拟 |
| `conversion.py` | 附录 B | 密钥转换与交叉认证 |
| `laboratory.py` | 辅助 | 查找私有网络的节点和端口 |

其他实验可能使用 `../实验室/` 下的独立脚本。加密测试向量及已签名数据必须保持**逐字节不变**，不得当作自然语言翻译。尤其是，`pow.py` **并未实现 Equi-X**，而是模拟其解以研究 Blake2b 层。

## 范围与安全限制

该教学客户端未实现完整的拥塞控制、电路轮换、填充以及全部流量分析防护机制。**不要用它保护真实身份、处理敏感流量，或将实验连接至公共 Tor 中继。** 实际隐私保护应使用保持更新的官方 Tor 或 Arti 软件。私有 Tor 实验网络也不等于与宿主操作系统隔离。