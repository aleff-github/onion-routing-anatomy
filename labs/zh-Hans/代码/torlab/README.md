# torlab — 教学用 Tor 客户端（简体中文版）

这个小型、可读的 Python 教学包配合本书的 **Tor 私有实验网络** 使用，**不是**可用于真实匿名通信的完整 Tor 客户端。不要用它保护真实身份，也不要把交互式实验连接到公共 Tor 中继。实际匿名使用应选择 Tor Browser 或 Arti。私有网络配置参见 [`../../实验室/`](../../实验室/README.md)。

| 实验 | 章节 | 模块 | 主题 |
|---|---|---|---|
| 1 | 07 | `channel.py` | TLS 通道、VERSIONS、CERTS、NETINFO 和身份检查 |
| 2 | 08 | `cells.py` | 定长与变长 cell 编解码及 relay cell 封装 |
| 3 | 09 | `ntor.py` | CREATE_FAST、ntor/ntor-v3、CREATE2/CREATED2、EXTEND2 |
| 4 | 10 | `encryption.py`, `circuit.py` | 分层加密、摘要与电路构建 |
| 5 | 11 | `stream.py` | BEGIN/DATA/END、SENDME 与流量控制 |
| 6 | 12 | `directory.py` | 共识文档、证书、中继信息与微描述符 |
| 7 | 13 | `path_selection.py` | 依照共识权重选择 Guard/Middle/Exit |
| 8 | 14 | `onion.py` | v3 onion 地址、密钥盲化、HSDir 与描述符 |
| 9 | 15 | `pow.py` | Blake2b 接受阈值：**不包含 Equi-X 的统计模拟** |
| 12 | 20 | `traffic.py` | 从已解密 TLS 跟踪中读取 Tor cell |
| 15 | 24 | `metrics.py` | 网络统计与示例用户数量估算 |
| 19 | 29 | `simulation.py` | 简化的 TorPS 风格失陷模型 |
| 附录 B | B | `conversion.py` | Montgomery/Edwards 转换与交叉证书 |
| 辅助工具 | 19 | `laboratory.py` | 私有实验网络的中继身份和密钥 |

### 运行测试

从**仓库根目录**，在隔离环境安装项目需要的 Python 测试依赖后：

```bash
PYTHONPATH=labs/zh-Hans/代码 python3 -m pytest -q labs/zh-Hans/代码/torlab/test
```

PowerShell：

```powershell
$env:PYTHONPATH = "labs/zh-Hans/代码"
python -m pytest -q labs/zh-Hans/代码/torlab/test
```

命令仅供复现，**不代表测试已通过**。`test/data/` 包含加密文档与抓包样例，翻译时不得修改其原始字节。

### 协议边界与数据来源

- **实验 7：** 处理共识带宽权重（含 `bwweightscale`）、中继身份和 IPv4 `/16`，未实现全部中继家族、出口策略、IPv6 约束或持久 Guard 机制。私有实验共识不能替代指定日期的公共共识。
- **实验 8：** 历史样例用于理解证书签名及加密。解析器默认 `check_expiration=False` 以兼容归档样例；处理实时数据必须另行验证证书期限和目录真实性。未实现 restricted discovery 与完整的引入点检查。
- **实验 9：** `required_attempts()` 使用随机的 **16 字节替代值**，而非 Equi-X 解。达到 `max_attempts`（默认 **10,000**）时可能抛出 `RuntimeError`。通过 Blake2b 阈值检查**不等于**有效的 Tor PoW。
- **实验 12、15、19：** 跟踪分析、网络指标与模拟需要相应历史数据。公共网络的统计示例需要额外验证的数据集，私有实验样例不能代替。模拟结果不能作为匿名性保证。

不同译本应保持 API 名称、协议字节和加密测试向量一致。
