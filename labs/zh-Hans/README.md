# 实验环境 — 简体中文

本目录是《Tor 解剖：逐字节解析匿名协议》的简体中文实验环境。

中文版源代码和文档保存在独立目录，但这**不意味着 Docker 容器或网络完全隔离**。EN、RU 和 ZH-CN 版本使用相同的镜像名 `torbook-lab:latest`、容器名 `torbook-network`，而且通过 `--network host` 共用宿主机网络和端口，**不能同时启动**。协议行为及测试向量保持一致；读者可见的说明、注释与诊断信息使用简体中文，Python API 和协议标识符仍保持原样。

目录：

- `实验室/` — 私有 Tor 网络、Docker 镜像和实验脚本；
- `代码/` — `torlab` 教学客户端、测试和可复现夹具；
- `维基/` — 实验 1–20 的简体中文文档。

可执行实验**只能针对受控的私有 Chutney 网络**，不得对公共 Tor 中继或第三方服务运行。由于 `--network host` 没有容器级网络隔离，请使用受控测试主机。`实验室/net/` 包含生成的节点身份和私钥，**不得公开**。

从仓库根目录执行：

```bash
make -C labs/zh-Hans test
make -C labs/zh-Hans image
make -C labs/zh-Hans start
make -C labs/zh-Hans verify
```

意大利文和英文版本的文件分别位于 `labs/it/` 与 `labs/en/`；目录独立不代表网络隔离。

## 命令的实际范围

- `make -C labs/zh-Hans test` 仅运行 `torlab` 单元测试，**并非运行书中全部 20 个实验**。
- `make -C labs/zh-Hans verify` 先运行上述测试，再执行 Chutney 的网络验证；不能以此证明所有独立实验脚本均通过。
- `make -C labs/zh-Hans data` 只在用户明确执行时通过 HTTPS 下载历史 CollecTor 公开数据。下载器**只检查格式标头，不验证共识签名或目录权威证书**。
- `make -C labs/zh-Hans stop` 保留 `实验室/net/`；`make -C labs/zh-Hans clean` 则会**删除 `实验室/net/` 内生成的密钥、节点身份和状态**。

进入容器请使用 `make -C labs/zh-Hans/实验室 shell`。如需实验 10 的 12 节点 obfs4 网桥拓扑，应先停止现有网络并检查、清理可丢弃的状态，再运行 `make -C labs/zh-Hans/实验室 start NETWORK=book-bridge`。与 10 节点的 `book` 不同，网桥拓扑不包含洋葱服务。完整说明见[实验 README](实验室/README.md)。

