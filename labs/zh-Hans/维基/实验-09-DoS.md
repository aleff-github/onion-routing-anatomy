# 实验 9 — 触发抗 DoS 防御

| 项目 | 内容 |
|---|---|
| **章节** | 15 — 拒绝服务攻击与防御 |
| **需要网络？** | 是；镜像必须使用 `--enable-gpl` 构建 |
| **前置实验** | 实验 1–8 |
| **预计时间** | 约两小时 |
| **文件** | `labs/zh-Hans/代码/torlab/pow.py` |

> **只能在自己的私有网络上执行。** 本实验故意生成异常流量。针对真实中继或洋葱服务重复这些操作，会干扰其他用户，也可能违法；参见第 25 章。

## 实验目的

**实验范围：**30 次请求仅接受 9 次是特定 Tor 版本和历史环境中的观察值，**不是永远固定的结果**。令牌桶会随时间补充，限制状态也取决于客户端源地址。所有操作仅限用户自己的可丢弃 Chutney 私有网络，绝不可指向公共中继。

可以从外部观察中继的抗 DoS 防御，而且实际行为比粗略阅读文档所得到的印象更复杂。原始试验中，将令牌桶突发上限设置为 10，却只允许建立 **9** 条电路，从第十次开始拒绝；来自 `127.0.0.1` 的连接也**没有获得豁免**。

本实验还研究洋葱服务工作量证明：如何启用、描述符中会增加什么，以及为什么预期工作量近似线性增长。

## 准备

如果镜像尚未构建，请先运行 `make -C labs/zh-Hans/实验室 image`。`start` 需要已有镜像。应分别确认 PoW 模块和 GPL 编译选项：

```bash
make -C labs/zh-Hans/实验室 start
export PYTHONPATH=labs/zh-Hans/代码
```

镜像必须包含启用 GPL 功能的工作量证明模块。仓库 Dockerfile 已配置相应构建选项：

```bash
docker run --rm torbook-lab:latest tor --list-modules
docker run --rm torbook-lab:latest tor --version
```

`tor --list-modules` 的 `pow: yes` 表明包含可选 PoW 模块。仍要从 `tor --version` 单独确认 GPL 编译选项，以启用 Equi-X。

## 第一部分：电路创建次数限制

**修改配置前**应确保仅运行对应的私有网络。HUP 应根据该节点在容器里的 PID 文件精确发送，不能用模糊的进程名匹配。`finally` 会恢复文本，但如果信号或重载失败，仍应检查实际文件与日志。

实验会临时在 `003r` 的 `torrc` 末尾加入很低的抗 DoS 阈值，重新加载中继，连续发送 30 条 `CREATE_FAST` 请求，并在 `finally` 中恢复原始配置。

```bash
python3 - <<'EOF'
import subprocess, time
from collections import Counter
from torlab.channel import open_channel
from torlab.cells import Cell, CellCommand
from torlab.laboratory import relay, NODES
from torlab.ntor import create_fast_client

torrc = NODES / "003r" / "torrc"
original = torrc.read_text()
hup = ["docker", "exec", "torbook-network", "sh", "-c",
       "kill -HUP $(cat /lab/net/nodes/003r/pid)"]
try:
    torrc.write_text(original + """
DoSCircuitCreationEnabled 1
DoSCircuitCreationMinConnections 2
DoSCircuitCreationRate 1
DoSCircuitCreationBurst 10
DoSCircuitCreationDefenseType 2
DoSCircuitCreationDefenseTimePeriod 60 seconds
""")
    subprocess.run(hup, check=True); time.sleep(2)
    g = relay("003r")
    for source, channel_count in (("127.0.0.2", 2), ("127.0.0.3", 1), ("127.0.0.1", 2)):
        channels = [open_channel("127.0.0.1", g.port, expected_identity=g.id_ed, source_address=source)
                    for _ in range(channel_count)]
        results, reasons, first_rejection = [], Counter(), None
        for i in range(30):
            x, body = create_fast_client()
            channels[0].send(Cell(0x80000100 + i, CellCommand.CREATE_FAST, body))
            r = channels[0].receive()
            while r.command in (CellCommand.PADDING, CellCommand.VPADDING):
                r = channels[0].receive()
            ok = r.command == CellCommand.CREATED_FAST
            results.append(ok)
            if not ok:
                reasons[r.body[0]] += 1
                first_rejection = first_rejection or i + 1
        m = ", ".join(f"DESTROY({k})" for k in reasons)
        print(f"源地址 {source}，通道数 {channel_count}：成功 {results.count(True)}，"
              f"拒绝 {30-results.count(True)} {m or '-'}；首次拒绝：{first_rejection}")
finally:
    torrc.write_text(original)
    subprocess.run(hup)
EOF
```

```text
源地址 127.0.0.2，通道数 2：成功 9，拒绝 21 DESTROY(5)；首次拒绝：10
源地址 127.0.0.3，通道数 1：成功 30，拒绝 0 -；首次拒绝：None
源地址 127.0.0.1，通道数 2：成功 9，拒绝 21 DESTROY(5)；首次拒绝：10
```

输出标签已与中文代码保持一致。**历史示例结果，而非固定验收条件：**请求期间令牌桶可能恢复，连接速度与先前状态也会影响结果。应该记录实际事件及原因码，不应假定所有运行都恰好接受九次。

三个关键结论：

1. 拒绝回应是**原因码 5 的 `DESTROY`**，即 `RESOURCELIMIT`。
2. 配置突发上限 10，原始实验却只接受 **9** 条电路。实现会在桶中令牌降到零时立即标记客户端，因此第十次就遭到拒绝。
3. 如果**只有一条通道**，本实验配置下防御不会触发，因为 `MinConnections` 要求至少两条并发连接。

实验还推翻了最初关于环回地址豁免的假设：`dos.c` 中这项限制并没有针对 loopback 的例外。

各轮试验采用不同源地址，以确保每轮从独立的计数身份开始。一个地址被标记之后，在配置的防御周期内会持续受到限制。

## 第二部分：洋葱服务工作量证明

这是 onion 服务配置的持久修改，而非临时 Python 测试。先备份 `009h/torrc`，加入选项后通过该节点 PID 重载；实验结束后**恢复原文件并再次重载**。若失败，应重建一次性实验网络而不是保留未知配置。

`pow-params` 是历史示例，种子、UTC 过期时间和推荐工作量会变。推荐值 0 表示此刻不强制消耗 PoW，不能仅凭此证明服务队列为空。种子更新的推荐窗口是随机选取的 105–120 分钟。

在 `009h` 的 `torrc` 中，在 HiddenService 配置行之后加入：

```text
HiddenServicePoWDefensesEnabled 1
```

然后仅在私有实验网络中重新加载相应服务：

```bash
docker exec torbook-network sh -c 'kill -HUP $(cat /lab/net/nodes/009h/pid)'
```

重新加载后，服务会发布新描述符。通过[实验 8](实验-08-洋葱服务.md)获取描述符，可以在第二层看到 `pow-params`：

```text
pow-params v1 9qe8kJUi30tgcAlInd5a+trFeVl1yjQtPRb0F4u9C7Y= 0 2026-09-24T17:56:10
```

这一行依次包含方案版本 `v1`、base64 编码的种子、推荐工作量，以及种子过期时间。历史运行中推荐工作量为零，因为服务当时没有积累待处理队列。

发送 `HUP` 后，应等待新描述符完成发布并在私有网络中传播。

## 第三部分：工作量近似线性增长

**此处只有 Blake2b 门槛的蒙特卡洛模拟，并未实现 Equi-X。**随机生成的 16 字节 `solution` 不是合法的 Equi-X 解。真实 v1 PoW 需要同时通过 Equi-X 和 Blake2b；此处只测量第二层接受概率。对均匀分布的 32 位 `R`，正数 `effort` 的成功概率近似为 `1/effort`。

Python 标准库不实现 Equi-X；因此原始教学实验提取了基于 Blake2b 的接受条件，以随机候选解演示工作量与成功概率的关系。

```bash
python3 - <<'EOF'
import os, statistics
from torlab.pow import required_attempts
id_service, seed = os.urandom(32), os.urandom(32)
for effort in (1, 10, 100, 1000):
    trials = [required_attempts(effort, id_service, seed) for _ in range(400)]
    print(f"工作量 {effort:>4}：平均 {statistics.mean(trials):.1f} 次")
EOF
```

```text
工作量    1：平均 1.0 次
工作量   10：平均 10.5 次
工作量  100：平均 90.0 次
工作量 1000：平均 1027.7 次
```

候选解随机，因此每次运行的精确值都会变化；但预期尝试次数大致与工作量参数成正比。

原始研究记录了一个容易犯的错误：Blake2b 设置 `digest_size=4`，**并不等价于**先计算通常的 64 字节 Blake2b 摘要再截取前四字节，因为输出长度属于 Blake2 参数块，改变长度也会改变哈希计算本身。

## 自动验证

意大利语历史 `lab9` 在运行中的私有网络上使用两条通道和新的源地址，检查参考案例的九次接受结果。本页面另外提供一条与两条连接的比较。离线 `test_pow.py` 检查 Blake2b 门槛及统计均值（努力值 10 和 40 各取 300 次），不测试真实 DoS 或 Equi-X。

可单独运行离线 PoW 单元测试：

```bash
PYTHONPATH=labs/zh-Hans/代码 python3 -m pytest -q labs/zh-Hans/代码/torlab/test/test_pow.py
```

`lab9` 覆盖第一部分，并检查历史记录中 30 次尝试接受 9 次的行为。第二、三部分不包含在自动测试套件中：第二部分会修改洋葱服务配置并等待描述符发布；第三部分属于统计试验，不存在单一的确定性输出。

## 常见问题

| 现象 | 原因 |
|---|---|
| 30 次请求从一开始就全部被拒绝 | 该源地址可能在上次测试后仍被标记；等待防御周期结束，或换用另一测试专用 loopback 地址 |
| 两条通道仍没有触发拒绝 | 中继可能没有成功重新加载配置；检查 `003r` 的 `notice.log` |
| 描述符中没有 `pow-params` | 镜像可能未使用 `--enable-gpl`，或者新描述符尚未发布 |
