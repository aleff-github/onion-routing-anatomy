# 实验 17 — RELAY_EARLY cell 数量限制

| 项目 | 内容 |
|---|---|
| **章节** | 27 — 网络遭受攻击的真实案例 |
| **需要网络？** | 是，仅使用本书的私有 Chutney 网络 |
| **前置实验** | 实验 1–4；Docker 与私有网络已准备 |
| **预计时间** | 约一小时 |
| **脚本** | `labs/zh-Hans/实验室/relay_early.py` |

## 实验目的和约束

对于**从客户端发往网络**的 `RELAY_EARLY` cell，Tor 为每条电路规定了**八条的配额**。当节点在同一出站电路上收到超过八条时，规范使用 **SHOULD（应当）**，建议关闭电路，而非 **MUST（必须）**。因此不能保证每种实现都会返回原因码 1 的 `DESTROY`。相反，节点收到**发往客户端方向**的 `RELAY_EARLY` 时，规范要求 **MUST（必须）**立即关闭电路。

**2014 年**，恶意 HSDir 与入口守卫中继串通，利用 `RELAY` 和 `RELAY_EARLY` 在外层头部可见的类型差异，向**客户端方向**传递隐蔽标记。这种标记可能将客户端 IP 与**洋葱服务描述符请求**联系起来，但**不能证明用户实际访问了网页**。八条的出站限制早在 2008 年就已存在；2014 年的修复强化了对反向异常 cell 的拒绝。

**关键方法限制：**本脚本与私有节点 `004r` 建立**单跳电路**，故意把加密的 **`DROP` 消息放入 `RELAY_EARLY` cell**。这种做法**不符合普通 Tor 客户端的规范**：客户端只能在 `RELAY_EARLY` 中使用 `EXTEND`/`EXTEND2`。这是一项**故意采用非标准输入的教学探测**，不是完整的协议一致性测试。

## 准备

从仓库根目录运行。首次使用先构建镜像，然后仅启动当前语言的私有网络；不同版本可能使用相同的宿主机端口。

```bash
# 首次执行：make -C labs/zh-Hans/实验室 image
make -C labs/zh-Hans/实验室 start
export PYTHONPATH=labs/zh-Hans/代码
```

## 执行实验

```bash
python3 labs/zh-Hans/实验室/relay_early.py 8 9
```

两个数字表示在**分别新建的电路**上发送八条和九条测试 cell。脚本只接受 **8 与 9**，禁止重复值，使用 `finally` 关闭通道，若未观察到历史预期结果则返回非零状态。在发送携带 `DROP` 的实验性 cell 后，脚本通过 `BEGIN_DIR` 检查电路是否还能建立目录流。

## 历史输出示例（并非固定结果）

```text
8 条 RELAY_EARLY cell -> CONNECTED
9 条 RELAY_EARLY cell -> 电路已被销毁，原因码 1
```

- **八条：**历史测试的 `BEGIN_DIR` 返回 `CONNECTED`。这**不表示**所有实现都必须接受 `RELAY_EARLY` 中的 `DROP`。
- **九条：**历史示例的 `DESTROY` 原因码为 **1**（`PROTOCOL`）；但规范仅规定 **SHOULD** 关闭，并没有要求总是返回特定代码。更早的拒绝或其他响应也不能直接视为协议错误。
- 八条的配额针对**每条电路**。多跳扩展会消耗一部分配额；这里故意使用由 `CREATE2` 建立的**单跳电路**，避免混入扩展消耗。

本实验**不重现 2014 年的入站信号攻击**，因为探测方向相反。相邻中继可以识别外层类型，但旁观链路加密 TLS 数据的普通观察者不能直接读取该标签。

## 自动验证和故障排查

**意大利语**参考验证器 `scripts/verify_labs.py::lab17` 只比较两行固定输出，**没有验证子进程返回状态**；因而可能把符合 SHOULD 条款的另一种行为误判为失败。脚本在结果与参考不符时明确返回错误状态。

| 现象 | 排查建议 |
|---|---|
| 八条测试就失败 | `RELAY_EARLY` 携带 `DROP` 是刻意的非标准行为；检查 Tor 版本及私有中继日志。 |
| 第九条没有返回原因码 1 | SHOULD 不保证这个具体返回码，应记录真实行为。 |
| 创建电路时出现 `CircuitError` | 检查 `004r` 和 Chutney 引导状态；禁止在公共中继上测试。 |

资料：[Tor Specification — RELAY_EARLY](https://spec.torproject.org/tor-spec/relay-early.html)；[Tor Project 2014 年安全公告](https://blog.torproject.org/tor-security-advisory-relay-early-traffic-confirmation-attack/)。
