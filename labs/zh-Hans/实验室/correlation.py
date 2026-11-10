# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 实验 16：仅在私有网络中对自己生成的合成流量进行时间相关性分析。
# 明文标识只用于评估结果，不代表对中继进行了被动抓包。
from __future__ import annotations

import math
import random
import socket
import socketserver
import statistics
import struct
import sys
import threading
import time

N, DURATION, BIN, BLOCK = 6, 20.0, 0.25, 2048
SERVER_PORT, SOCKS = 8095, ("127.0.0.1", 9008)
arrivals: dict[int, list[tuple[float, int]]] = {}
sends: dict[int, list[tuple[float, int]]] = {}
ground_truth: dict[int, int] = {}  # 只用于评价结果，不参与计算配对。
flow_lock = threading.Lock()


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        fragment = sock.recv(count - len(data))
        if not fragment:
            raise ConnectionError("SOCKS 或流响应不完整")
        data.extend(fragment)
    return bytes(data)


class Receiver(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(40)
        try:
            # 发送合成编号，仅用于评价匹配的正确性。
            index = struct.unpack(">I", recv_exact(self.request, 4))[0]
            if index >= N:
                return
            records: list[tuple[float, int]] = []
            with flow_lock:
                flow_id = len(arrivals)
                ground_truth[flow_id] = index
                arrivals[flow_id] = records
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                records.append((time.monotonic(), len(data)))
        except (ConnectionError, OSError):
            return


class LabServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def socks5(credentials: str) -> socket.socket:
    """私有 SOCKS5 完整读取响应，只连接本地地址 8095。"""
    user = credentials.encode("utf-8")
    if not 1 <= len(user) <= 255:
        raise ValueError("SOCKS 用户名长度必须介于 1..255")
    sock = socket.create_connection(SOCKS, timeout=15)
    try:
        sock.settimeout(15)
        sock.sendall(b"\x05\x01\x02")
        if recv_exact(sock, 2) != b"\x05\x02":
            raise ConnectionError("SOCKS5 用户名密码验证不可用")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + b"\x01x")
        if recv_exact(sock, 2) != b"\x01\x00":
            raise ConnectionError("SOCKS5 凭据被拒绝")
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                     + struct.pack(">H", SERVER_PORT))
        version, status, reserved, atyp = recv_exact(sock, 4)
        if version != 5 or status != 0 or reserved != 0:
            raise ConnectionError(f"SOCKS5 连接失败：{status}")
        if atyp == 1:
            recv_exact(sock, 4)
        elif atyp == 4:
            recv_exact(sock, 16)
        elif atyp == 3:
            recv_exact(sock, recv_exact(sock, 1)[0])
        else:
            raise ConnectionError("SOCKS5 返回了无效的地址类型")
        recv_exact(sock, 2)  # BND.PORT
        sock.settimeout(45)
        return sock
    except BaseException:
        sock.close()
        raise


def client(i: int, rng: random.Random, start: float) -> None:
    sends[i] = []
    # 不同 SOCKS 授权上下文并不保证使用不同电路。
    with socks5(f"flow-{i}") as sock:
        sock.sendall(struct.pack(">I", i))  # 只用于验证结果的编号，不参与相关计算。
        while time.monotonic() - start < DURATION:
            if rng.random() < 0.5:
                for _ in range(rng.randint(5, 40)):
                    sock.sendall(b"\0" * BLOCK)
                    sends[i].append((time.monotonic(), BLOCK))
            time.sleep(rng.uniform(0.2, 1.0))


def series(events, start):
    bins = [0] * int(DURATION / BIN + 20)
    for timestamp, size in events:
        if timestamp < start:            # int() 向零截断：-0.01 会落入第 0 个区间
            continue
        idx = int((timestamp - start) / BIN)
        if 0 <= idx < len(bins):
            bins[idx] += size
    return bins


def safe_correlation(a, b) -> float:
    """常量或缺失序列不能得到有效的皮尔逊相关系数。"""
    if len(a) != len(b) or len(a) < 2 or len(set(a)) < 2 or len(set(b)) < 2:
        return float("-inf")
    try:
        score = statistics.correlation(a, b)
    except (statistics.StatisticsError, ValueError):
        return float("-inf")
    return score if math.isfinite(score) else float("-inf")


def main() -> None:
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    arrivals.clear()
    sends.clear()
    ground_truth.clear()
    errors: list[tuple[int, Exception]] = []

    def worker(i: int, start: float) -> None:
        try:
            client(i, random.Random(seed * 100 + i), start)
        except Exception as exc:
            errors.append((i, exc))

    with LabServer(("127.0.0.1", SERVER_PORT), Receiver) as server:
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            start = time.monotonic()
            threads = [threading.Thread(target=worker, args=(i, start)) for i in range(N)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            time.sleep(3)
        finally:
            server.shutdown()
            server_thread.join()

    if errors:
        raise RuntimeError(f"客户端 {errors[0][0]} 失败：{errors[0][1]}") from errors[0][1]
    if len(sends) != N or len(arrivals) != N:
        raise RuntimeError("合成流量不足")

    entry_series = {i: series(events, start) for i, events in sends.items()}
    exit_flow = {k: series(events, start) for k, events in arrivals.items()}
    correct = 0
    for i, entry in sorted(entry_series.items()):
        scores = {k: safe_correlation(entry, exit_) for k, exit_ in exit_flow.items()}
        if not any(math.isfinite(score) for score in scores.values()):
            raise RuntimeError("没有可以比较的非恒定时间序列")
        best = max(scores, key=scores.get)
        matched = ground_truth[best] == i
        correct += int(matched)
        values = " ".join(f"{scores[k]:+.2f}" for k in sorted(exit_flow))
        label = "匹配" if matched else "错误"
        print(f"客户端 {i}: {values}  -> 出口流 {best} {label}")
    print(f"正确匹配数: {correct}/{len(entry_series)}")
    if correct < 5:
        raise RuntimeError("六个匹配结果中正确数少于五个")


if __name__ == "__main__":
    main()
