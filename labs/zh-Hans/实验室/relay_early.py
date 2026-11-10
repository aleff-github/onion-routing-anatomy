# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 实验 17（第 27 章）：八条 RELAY_EARLY 的上限早于 2014 年；2014 年的修复拒绝发往客户端的异常 cell。
# 与 004r 建立单跳电路，发送 N 条承载 DROP 消息的 RELAY_EARLY cell
# （中继会直接丢弃这些消息），然后建立目录流，检查电路是否仍然可用。
import sys
from torlab.cells import Cell, CellCommand, RelayCommand, RelayMessage
from torlab.circuit import Circuit, CircuitError, build
from torlab.laboratory import relay


def test_destination(n: int) -> str:
    """非规范的 RELAY_EARLY 与 DROP 示例；仅使用私有节点 004r。"""
    if n not in (8, 9):
        raise ValueError("只能使用 8 或 9 条 RELAY_EARLY cell。")
    circ = build([relay("004r")], cc=False)
    try:
        for _ in range(n):
            # 按照 tor-spec，客户端不能在 RELAY_EARLY 中发送 DROP。
            body = circ.crypto.encrypt(RelayMessage(RelayCommand.DROP, 0), None)
            circ.channel.send(Cell(circ.circ_id, CellCommand.RELAY_EARLY, body))
        circ.send(RelayMessage(RelayCommand.BEGIN_DIR, 1))
        _, response = circ.receive()
        return RelayCommand(response.command).name
    except CircuitError as exc:
        return str(exc)
    finally:
        circ.channel.sock.close()


def main() -> int:
    values = list(map(int, sys.argv[1:])) if len(sys.argv) > 1 else [8, 9]
    if not values or any(n not in (8, 9) for n in values) or len(values) != len(set(values)):
        raise SystemExit("只能使用 8 或 9 条 RELAY_EARLY cell。")
    results = {}
    for n in values:
        results[n] = test_destination(n)
        print(f"{n} 条 RELAY_EARLY cell -> {results[n]}")
    # 仅复现历史观察用于教学，并非 Tor 协议的 MUST 义务。
    return 0 if all(results[n] == ("CONNECTED" if n == 8 else "电路已被销毁，原因码 1") for n in values) else 1

if __name__ == "__main__":
    raise SystemExit(main())
