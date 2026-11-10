# 实验 20 — 在私有网络中运行 Arti

| 项目 | 内容 |
|---|---|
| **章节** | 30 — 使用 Rust 重写 Tor 的 Arti |
| **需要网络？** | 是；还需要 Rust 工具链编译 Arti |
| **前置条件** | 私有网络正在运行；已安装 `cargo` |
| **预计时间** | 约一小时，另加编译时间 |
| **文件** | `labs/zh-Hans/实验室/arti_config.py` |

## 实验目的

本书的私有网络并不是只供 C 语言版 tor 使用的专有网络，而是遵循 Tor 协议的网络。另一种实现也能够加入网络、下载目录信息、建立电路，并通过 C 语言实现的中继转发流量；中继无须知道客户端究竟使用哪一种实现。

这表明本书研究的是能够跨实现互操作的**协议格式**，而非某个实现自己的约定。

## 准备

为复现**受控私有网络**中的历史实验，构建固定版本 Arti 2.6.0。此版本并非公共 Tor 网络的推荐部署版本：后续版本（包括 2026 年 10 月发布的 Arti 2.7.0）修复了安全问题。源码位于 Tor Project 的仓库：

```bash
mkdir -p labs/zh-Hans/vendor
git clone https://gitlab.torproject.org/tpo/core/arti.git labs/zh-Hans/vendor/arti
git -C labs/zh-Hans/vendor/arti checkout arti-v2.6.0
(cd labs/zh-Hans/vendor/arti && cargo build --release -p arti --locked)
```

然后返回仓库根目录，生成实验网络配置：

```bash
export PYTHONPATH=labs/zh-Hans/代码
python3 labs/zh-Hans/实验室/arti_config.py
```

脚本从私有网络节点文件中读取权威节点身份与端口，写入 `labs/zh-Hans/实验室/net/arti/arti.toml`。配置包括私有权威节点与后备缓存、允许本地地址、因全部中继位于 loopback 而关闭子网多样性约束，以及缩短 HSDir 时间周期。

## 执行实验

请在仓库根目录的 POSIX shell 中运行以下命令；先使用 `make -C labs/zh-Hans/实验室 start` 启动私有实验网络（如果已经启动，请勿重复启动）。测试同时验证 **HTTP 状态码** 和固定的响应正文，以免把占用 8080 端口的其他服务误认为实验服务器。下面的服务器不会公开工作目录中的文件。

```sh
(
set -eu
ARTI_BIN="labs/zh-Hans/vendor/arti/target/release/arti"
ARTI_CFG="labs/zh-Hans/实验室/net/arti/arti.toml"
ARTI_LOG="labs/zh-Hans/实验室/net/arti/arti.log"
HTTP_LOG="labs/zh-Hans/实验室/net/arti/http.log"
ARTI_PID=
HTTP_PID=
BODY_FILE=

cleanup() {
  if [ -n "$HTTP_PID" ]; then
    kill "$HTTP_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
  fi
  if [ -n "$ARTI_PID" ]; then
    kill "$ARTI_PID" 2>/dev/null || true
    wait "$ARTI_PID" 2>/dev/null || true
  fi
  if [ -n "$BODY_FILE" ]; then rm -f "$BODY_FILE"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[ -x "$ARTI_BIN" ] && [ -f "$ARTI_CFG" ] || {
  echo "缺少 Arti 可执行文件或私有网络配置" >&2
  exit 1
}
: > "$ARTI_LOG"
"$ARTI_BIN" proxy -c "$ARTI_CFG" > "$ARTI_LOG" 2>&1 &
ARTI_PID=$!

# 等待当前 Arti 进程完成引导
ready=0
n=0
while [ "$n" -lt 60 ]; do
  if grep -q "proxy now functional" "$ARTI_LOG" && kill -0 "$ARTI_PID" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$ARTI_PID" 2>/dev/null; then
    echo "Arti 在引导完成前退出，请检查 $ARTI_LOG" >&2
    exit 1
  fi
  n=$((n + 1))
  sleep 2
done
[ "$ready" -eq 1 ] || {
  echo "Arti 引导未完成，请检查 $ARTI_LOG" >&2
  exit 1
}

# 本地 HTTP 服务器：仅在 / 返回固定响应
python3 -u - > "$HTTP_LOG" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = b"arti-private-lab-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
PY
HTTP_PID=$!
sleep 1
kill -0 "$HTTP_PID" 2>/dev/null || {
  echo "本地 HTTP 服务器启动失败，请检查 $HTTP_LOG" >&2
  exit 1
}

BODY_FILE=$(mktemp)
HTTP_CODE=$(curl --fail --silent --show-error --max-time 30 \
  --noproxy "" --socks5-hostname 127.0.0.1:9150 \
  -o "$BODY_FILE" -w '%{http_code}' http://127.0.0.1:8080/)
[ "$HTTP_CODE" = "200" ] && [ "$(cat "$BODY_FILE")" = "arti-private-lab-ok" ] || {
  echo "私有实验网络返回了意外的 HTTP 响应" >&2
  exit 1
}
printf '%s\n' "$HTTP_CODE"
)
```

此示例会清空旧日志、确认本次启动的 Arti 进程仍在运行、在 8080 端口被占用时报告失败，并在可捕获的错误或中断后只清理**自己创建的进程**，而不是用 `pkill` 结束其他实例。只有当 `curl` 成功退出、HTTP 状态码为 `200` 且响应正文是 `arti-private-lab-ok` 时，才认为测试通过。本实验依靠**私有网络出口节点**连接本地服务器，不代表公共 Tor 网络允许回环地址访问。

## 参考输出

```text
2026-09-24T16:05:45Z  INFO arti::subcommands::proxy: Sufficiently bootstrapped; proxy now functional.
200
```

解释：Arti 从私有权威节点下载并验证目录信息，完成引导并构建电路，然后通过同一组中继代理 HTTP 请求。上面的日志与 HTTP 状态码来自参考运行。中继不需要针对 Rust 客户端采取特殊处理。

空的 `--noproxy ""` 参数可确保本地请求不会因为环境变量 `NO_PROXY` 而绕过 SOCKS。本实验中的 Arti SOCKS 默认端口为 **9150**，与 Tor Browser 的惯例一致，而独立 tor 客户端通常使用 9050。

## Arti 与 tor 有哪些区别？

Arti 使用 TOML 配置，而不是 `torrc`。私有权威节点条目需要 `rsa_identity`、`ed_identity` 和 `orports` 等字段，同时提供传统 RSA 身份和 Ed25519 身份。

第 30 章进一步介绍其支持的功能及尚未实现的角色，包括当前不能直接把客户端 Arti 当作完整中继使用。

还有一个值得保留的源码校对发现：Arti 的 `Compatibility.md` 表格中，`FlowCtrl` 版本编号相对 torspec 偏移了一位。根据正式规范和观察到的公共共识（`FlowCtrl=1-2`），版本 1 对应 `AUTH_SENDME`，版本 2 对应拥塞控制。实现文档与协议规范冲突时，应回到规范并对照实际网络数据核实。

## 自动验证

意大利语参考检查器 `scripts/verify_labs.py::lab20` **并不自动验证此中文版步骤**：它使用根目录下的 `fonti/arti/target/release/arti` 和 `实验室/arti_config.py`，而此文档使用 `labs/zh-Hans/...`。若根目录二进制文件缺失，检查器报告的是**跳过而非通过**。

## 常见问题

| 现象 | 原因及处理 |
|---|---|
| `Lab 20: Arti binary not found; laboratory skipped` | 缺少 `labs/zh-Hans/vendor/arti/target/release/arti` |
| 一直无法完成引导 | 私有网络已停止，或 `arti.toml` 在上次重新生成网络前创建；重跑 `arti_config.py` |
| 状态目录出现 `Permission denied` | Arti 要求严格的目录权限；只删除可丢弃的 `labs/zh-Hans/实验室/net/arti/state` 再试 |
| `pkill -f "arti proxy"` 或 `pkill -x arti` 结束不相关进程 | 不要按进程名批量结束任务；上面的命令通过自身启动的 PID 和 `trap` 清理进程 |
