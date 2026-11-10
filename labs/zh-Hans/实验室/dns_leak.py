# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 18 — 在私有 Tor 网络中检测 SOCKS DNS 风险。

仅连接 localhost 和私有 Chutney 网络中的 008c 客户端。
SOCKS 警告并不能证明实际发生了 DNS 泄露。
"""
from __future__ import annotations

import http.server
from pathlib import Path
import re
import subprocess
import threading
import time

URL = "http://localhost:8080/"
SOCKS = "127.0.0.1:9008"
CONTROL_PORT = 8008
PRIVATE_CLIENT = Path("/lab/net/nodes/008c")


class LocalResponse(http.server.BaseHTTPRequestHandler):
    """仅返回固定文本，绝不公开 /lab 或其他目录中的文件。"""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = "私有 Tor 实验".encode("utf-8") + b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def check_environment() -> None:
    if not PRIVATE_CLIENT.is_dir() or not Path("/lab/chutney/networks/book").is_file():
        raise RuntimeError("仅允许在私有 Chutney 网络执行")


def request(option: str) -> tuple[str, int]:
    if option not in ("--socks5", "--socks5-hostname"):
        raise ValueError("实验不允许使用该 SOCKS 选项")
    result = subprocess.run(
        ["curl", "-4", "--silent", "--show-error", "--output", "/dev/null",
         "--write-out", "%{http_code}", "--max-time", "25", "--noproxy", "",
         option, SOCKS, URL],
        capture_output=True, text=True, timeout=30, check=False)
    status = result.stdout.strip()
    return (status if re.fullmatch(r"[0-9]{3}", status) else "000",
            result.returncode)


def restore_options(controller, previous: dict[str, str | None]) -> None:
    for name, value in previous.items():
        if value is None:
            controller.reset_conf(name)
        else:
            controller.set_conf(name, value)


def run_cases(controller, notice_type, warn_type) -> bool:
    messages: list[str] = []
    def record(event):
        messages.append(event.message)
    previous = {name: controller.get_conf(name, default=None)
                for name in ("TestSocks", "SafeSocks")}
    listening = False
    try:
        controller.add_event_listener(record, notice_type, warn_type)
        listening = True
        controller.set_options({"TestSocks": "1", "SafeSocks": "0"})
        all_ok = True
        for opt, marker in (("--socks5", "IP address"),
                            ("--socks5-hostname", "DNS resolution")):
            start = len(messages)
            status, returncode = request(opt)
            time.sleep(1)
            notification = next((m for m in messages[start:]
                                 if marker.casefold() in m.casefold()), "")
            print(f"{opt:18s} HTTP {status}  tor: "
                  f"{(notification or 'Tor 未发出通知')[:110]}")
            all_ok &= (status == "200" and returncode == 0
                       and bool(notification))
        controller.set_conf("SafeSocks", "1")
        denied, code = request("--socks5")
        print(f"{'--socks5 SafeSocks':18s} HTTP {denied}")
        all_ok &= (denied == "000" and code != 0)
        return bool(all_ok)
    finally:
        try:
            restore_options(controller, previous)
        finally:
            if listening:
                controller.remove_event_listener(record)


def main() -> int:
    check_environment()
    # 延迟导入 Stem，阅读源码无需连接 Tor。
    from stem.control import Controller, EventType
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), LocalResponse)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with Controller.from_port(address="127.0.0.1", port=CONTROL_PORT) as ctrl:
            ctrl.authenticate()
            passed = run_cases(ctrl, EventType.NOTICE, EventType.WARN)
        if not passed:
            raise RuntimeError("SOCKS/DNS 检查未全部通过")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    raise SystemExit(main())
