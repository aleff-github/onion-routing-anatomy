# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 实验 11（第 18 章）：使用 Stem 观察流隔离。
import re, subprocess, time
from stem import StreamStatus
from stem.control import Controller, EventType

DESTINATION = "127.0.0.1:8080"
SOCKS = "127.0.0.1:9008"

assigned, warnings = [], []


def on_stream(ev):
    # 只统计发往实验目标的流：tor 还会自行建立目录请求流，
    # 若计入会导致统计结果失真。
    if ev.status == StreamStatus.SUCCEEDED and ev.target == DESTINATION:
        assigned.append((ev.id, ev.circ_id, ev.target))


def tunnel(c, circ: str) -> str:
    """电路可能属于 Conflux 集合（两条关联的分支；参见第 31 章）；\n    此时隔离作用于整个集合，而不是其中某条分支。"""
    for row in c.get_info("circuit-status").splitlines():
        if row.split(" ", 1)[0] == circ:
            r = re.search(r"CONFLUX_ID=(\w+)", row)
            return f"conflux {r.group(1)[:8]}" if r else f"电路 {circ}"
    return f"电路 {circ}"


def wait_for_tunnel(c, seconds=30):
    """等待 tor 至少重新建立一套完整的 Conflux 分支（两条电路）。"""
    for _ in range(seconds * 2):
        sets = re.findall(r"^\d+ BUILT .*CONFLUX_ID=(\w+)", c.get_info("circuit-status"), re.M)
        if any(sets.count(x) >= 2 for x in sets):
            return
        time.sleep(0.5)


def request(c, credentials=None):
    """执行请求并返回 tor 为它使用的电路。
    采用最后一次事件：某次尝试失败后，tor 可能在另一条电路上重试，
    并再次发出 SUCCEEDED 事件。"""
    assigned.clear()
    cmd = ["curl", "--noproxy", "", "-s", "-o", "/dev/null", "--socks5-hostname", SOCKS, f"http://{DESTINATION}/"]
    if credentials:
        cmd[1:1] = ["--proxy-user", credentials]
    subprocess.run(cmd, check=True)
    for _ in range(20):
        time.sleep(0.5)
        if assigned:
            break
    if not assigned:
        return "?", []
    circ = assigned[-1][1]
    return tunnel(c, circ), [x[1] for x in c.get_circuit(circ).path]


def newnym(c, announce=False):
    """NEWNYM 每十秒最多执行一次（参见 src/core/mainloop/mainloop.c 的
    MAX_SIGNEWNYM_RATE）；提前提出的请求会被延迟并记录日志。
    必须等待信号真正生效，否则它可能在后续测试过程中才执行。"""
    warnings.clear()
    c.signal("NEWNYM")
    time.sleep(2)
    for m in list(warnings):
        r = re.search(r"Rate limiting NEWNYM request: delaying by (\d+) second", m)
        if r:
            if announce:
                print(f"（NEWNYM 延迟 {r.group(1)} 秒）")
            time.sleep(int(r.group(1)) + 1)


with Controller.from_port(port=8008) as c:
    c.authenticate()
    c.add_event_listener(on_stream, EventType.STREAM)
    c.add_event_listener(lambda ev: warnings.append(ev.message), EventType.NOTICE)
    newnym(c)                     # 从新电路开始，确保没有待执行的 NEWNYM
    wait_for_tunnel(c)             # 等待至少一条隧道可用，否则首批请求可能被分配到
                                  # 不同的新建隧道
    for credentials in ["site-a.example:x1", "site-a.example:x1", "site-b.example:x2", None]:
        circ, path = request(c, credentials)
        name = credentials.split(":")[0] if credentials else "-"
        print(f"凭据 {name:15s} -> {circ:22s} {path}")
    newnym(c, announce=True)
    circ, _ = request(c, "site-a.example:x1")
    print(f"NEWNYM 后，site-a.example -> {circ}")
