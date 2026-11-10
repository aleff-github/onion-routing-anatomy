# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 实验 14（第 22 章）：出口策略规则及其后果。
# 在 test006e 允许 127.0.0.0/8 的规则之前，添加拒绝某端口的规则，
# 然后测试三个目的地，并务必恢复原始 torrc。
import http.server
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

from torlab.cells import RelayCommand, RelayMessage
from torlab.circuit import CircuitError, build
from torlab.laboratory import relay
from torlab.stream import END_REASONS, begin_body

LAB = Path(__file__).resolve().parent
EXIT = LAB / "net" / "nodes" / "006e"
CONTAINER = "torbook-network"
OPEN_PORT, BLOCKED_PORT, NO_SERVER_PORT = 8081, 8080, 9999


class 固定响应(http.server.BaseHTTPRequestHandler):
    """仅返回固定测试文本，不提供本地文件。"""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = "Tor 私有出口策略测试\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass



def hup():
    # 仅针对 006e 的准确 PID，避免使用宽泛的进程名匹配。
    command = (
        'pid=$(cat /lab/net/nodes/006e/pid) || exit 1; '
        'case "$pid" in ""|*[!0-9]*) exit 1;; esac; '
        'args=$(ps -p "$pid" -o args=) || exit 1; '
        'case "$args" in *006e/torrc*) kill -HUP "$pid";; *) exit 1;; esac'
    )
    subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", command],
                   check=True, timeout=15)


def test_destination(port: int) -> str:
    """通过私有网络的三跳电路请求本地目标。"""
    if port not in (OPEN_PORT, BLOCKED_PORT, NO_SERVER_PORT):
        raise ValueError("目标端口必须是本实验指定的三个端口之一")
    circ = build([relay("003r"), relay("005r"), relay("006e")])
    try:
        circ.send(RelayMessage(RelayCommand.BEGIN, 1, begin_body("127.0.0.1", port)))
        try:
            _, response = circ.receive()
        except CircuitError as error:
            return str(error)
        if response.command == RelayCommand.CONNECTED:
            return "CONNECTED"
        if response.command != RelayCommand.END:
            raise RuntimeError("意外的响应" + f": {response.command}")
        reason = response.data[0] if response.data else 1
        suffix = ""
        if reason == 4 and len(response.data) == 9:
            ip = ".".join(str(b) for b in response.data[1:5])
            suffix = f" 地址={ip} TTL={int.from_bytes(response.data[5:9], 'big')}"
        return f"END reason={END_REASONS.get(reason, reason)}{suffix}"
    finally:
        circ.channel.sock.close()


def main():
    # 如果负向测试端口已被占用，就停止测试。
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.settimeout(0.25)
        if check.connect_ex(("127.0.0.1", 9999)) == 0:
            raise RuntimeError("端口 9999 已有监听服务：不能进行有效的负向测试")
    torrc = EXIT / "torrc"
    original = torrc.read_text()
    rule = "ExitPolicy reject 127.0.0.1:8080"
    if re.search(r"(?m)^\s*" + re.escape(rule) + r"\s*$", original):
        raise RuntimeError("拒绝规则已存在")
    match = re.search(r"(?m)^ExitPolicy\s+", original)
    if match is None:
        raise RuntimeError("006e 的 torrc 中没有 ExitPolicy 配置项")
    # 使用字符串切片插入规则，避免正则替换中的转义和反向引用错误。
    updated = original[:match.start()] + rule + "\n" + original[match.start():]
    servers = []
    modified = False
    try:
        for port in (8081, 8080):
            try:
                server = http.server.ThreadingHTTPServer(
                    ("127.0.0.1", port), 固定响应)
            except OSError as exc:
                if port == 8081:
                    raise RuntimeError("端口 8081 已被占用：正向测试需要空闲端口") from exc
                # 8080 端口可能已有本地测试 HTTP 服务。
                continue
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        try:
            # 在写入前标记状态，确保部分写入也会触发恢复。
            modified = True
            torrc.write_text(updated)
            hup()
            time.sleep(3)
            results = {}
            for port in (8080, 8081, 9999):
                results[port] = test_destination(port)
                print(f"127.0.0.1:{port} -> {results[port]}")
            valid = (results[8080].startswith("END reason=EXITPOLICY")
                     and results[8081] == "CONNECTED"
                     and results[9999] in ("END reason=MISC",
                                            "END reason=CONNECTREFUSED"))
            if not valid:
                raise RuntimeError("实验结果与预期类别不符")
        finally:
            if modified:
                torrc.write_text(original)
                try:
                    hup()
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    raise RuntimeError("无法重新加载原始 torrc：请立即检查节点 006e") from exc
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
