# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 12：从抓取并解密的通道中读取 cell。

以 tshark -q -z follow,tls,raw,N 对自己通道的抓包解密结果为输入；
TLS 密钥由自己的程序通过 SSLKEYLOGFILE 导出（第 20 章）。
"""
from __future__ import annotations

from .cells import Cell, CellCommand, decode


def cells_from_follow(text: str) -> list[tuple[str, Cell, int]]:
    """返回两个方向各条 cell 的（方向、cell、解析所用版本）。
    在这份教学抓包中，首个数据块是客户端的 VERSIONS；tshark 用 Tab 缩进一个方向。
    每次遇到 VERSIONS 后，解析器便假定链路版本为 5（4 字节 CircID）。
    它不会根据双方提供的版本列表计算实际协商版本。"""
    lines = [r for r in text.splitlines()
             if r.strip() and not r.startswith(("=", "Follow", "Filter", "Node"))]
    if not lines:
        return []
    client_indented = lines[0].startswith("\t")
    version = {"client": 0, "relay": 0}
    remaining = {"client": b"", "relay": b""}
    output = []
    for r in lines:
        direction = "client" if r.startswith("\t") == client_indented else "relay"
        remaining[direction] += bytes.fromhex(r.strip())
        while (x := decode(remaining[direction], version[direction])) is not None:
            cell, remaining[direction] = x
            output.append((direction, cell, version[direction]))
            if cell.command == CellCommand.VERSIONS and version[direction] == 0:
                version[direction] = 5
    return output
