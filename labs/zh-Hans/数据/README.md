# 公共历史研究数据

实验 **7、15 和 19** 使用归档的 Tor 微描述符共识。私有 Chutney
网络中的测试共识**不能替代**书中历史数值计算所需的公开快照。

为避免将较大的公开 CollecTor 数据重复提交至 Git 仓库，请从仓库根目录按需执行：

```bash
make -C labs/zh-Hans data
```

此命令调用 `labs/zh-Hans/fetch-public-data.sh`，通过普通 HTTPS 下载
Tor Project CollecTor 的 2026 年 9 月历史归档，并提取：

`2026-09-23-15-00-00-consensus-microdesc`

保存路径为：

`labs/zh-Hans/数据/collector/consensus-microdesc-2026-09-23-15`

脚本**仅检查文件格式的起始标头**，不验证共识的数字签名，
也不独立证明书中的历史数值结果可复现。签名验证需要相应的
目录权威证书；数值复现还需要实际执行相应的实验与检查。

下载不会向公共 Tor 中继发送实验流量；生成的快照已被
`.gitignore` 排除。

共识原始内容及测试向量属于不因语言版本而改变的技术数据；
翻译不应更改协议字段、签名、密钥标识或十六进制字节。
