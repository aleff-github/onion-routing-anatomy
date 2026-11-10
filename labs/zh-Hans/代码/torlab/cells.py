# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 2：Tor cell 的编码与解码。

规范依据：tor-spec 的 Cells、Relay cells、Message lengths 与
Negotiating versions with VERSIONS cells。
教学模块优先保证可读性，而不是性能。
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import IntEnum

CELL_BODY_LEN = 509          # 定长 cell 的消息体字节数
RELAY_HEADER_LEN = 11        # relay 消息头长度（传统格式）
RELAY_DATA_MAX = CELL_BODY_LEN - RELAY_HEADER_LEN   # 498


class CellCommand(IntEnum):
    """Command 字段可用的取值（tor-spec，cell-packet-format）。"""
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    VERSIONS = 7
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11
    PADDING_NEGOTIATE = 12
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132


class RelayCommand(IntEnum):
    """Relay 命令字段的取值（tor-spec，relay-cells）。"""
    BEGIN = 1
    DATA = 2
    END = 3
    CONNECTED = 4
    SENDME = 5
    EXTEND = 6
    EXTENDED = 7
    TRUNCATE = 8
    TRUNCATED = 9
    DROP = 10
    RESOLVE = 11
    RESOLVED = 12
    BEGIN_DIR = 13
    EXTEND2 = 14
    EXTENDED2 = 15
    CONFLUX_LINK = 19
    CONFLUX_LINKED = 20
    CONFLUX_LINKED_ACK = 21
    CONFLUX_SWITCH = 22
    ESTABLISH_INTRO = 32
    ESTABLISH_RENDEZVOUS = 33
    INTRODUCE1 = 34
    INTRODUCE2 = 35
    RENDEZVOUS1 = 36
    RENDEZVOUS2 = 37
    INTRO_ESTABLISHED = 38
    RENDEZVOUS_ESTABLISHED = 39
    INTRODUCE_ACK = 40
    PADDING_NEGOTIATE = 41
    PADDING_NEGOTIATED = 42
    XOFF = 43
    XON = 44


class CellError(ValueError):
    """格式错误的 cell 或协议不允许的 cell。"""


def circid_len(version: int) -> int:
    """CircID 的字节长度：链路版本 3 及更早为 2，版本 4 起为 4。"""
    return 2 if version < 4 else 4


def is_variable_length(command: int) -> bool:
    """VERSIONS（7）与编号不小于 128 的命令使用变长 cell。"""
    return command == CellCommand.VERSIONS or command >= 128


@dataclass
class Cell:
    circ_id: int
    command: int
    body: bytes = b""


def encode(cell: Cell, version: int) -> bytes:
    """按照链路协议 `version` 序列化 cell。

    VERSIONS 始终按版本 0 编码（两字节 CircID），
    因为发送时双方尚未协商链路协议版本。
    """
    if cell.command == CellCommand.VERSIONS:
        version = 0
    n = circid_len(version)
    if not 0 <= cell.circ_id < 1 << (8 * n):
        raise CellError(f"CircID {cell.circ_id:#x} 无法容纳在 {n} 字节中")
    # 按照 tor-spec，CircID 必须与命令所属类别一致。
    if cell.command in (
        CellCommand.PADDING, CellCommand.VERSIONS, CellCommand.NETINFO, CellCommand.VPADDING,
        CellCommand.CERTS, CellCommand.AUTH_CHALLENGE, CellCommand.AUTHENTICATE, CellCommand.AUTHORIZE,
    ) and cell.circ_id != 0:
        raise CellError("此类信元要求 CircID 为零")
    if cell.command in (
        CellCommand.CREATE, CellCommand.CREATED, CellCommand.RELAY, CellCommand.DESTROY,
        CellCommand.CREATE_FAST, CellCommand.CREATED_FAST, CellCommand.RELAY_EARLY,
        CellCommand.CREATE2, CellCommand.CREATED2, CellCommand.PADDING_NEGOTIATE,
    ) and cell.circ_id == 0:
        raise CellError("此类信元要求 CircID 非零")
    header = cell.circ_id.to_bytes(n, "big") + bytes([cell.command])
    if is_variable_length(cell.command):
        if len(cell.body) > 0xFFFF:
            raise CellError("变长 cell 的消息体过长")
        return header + struct.pack(">H", len(cell.body)) + cell.body
    if len(cell.body) > CELL_BODY_LEN:
        raise CellError(f"消息体长度 {len(cell.body)} 字节超过 {CELL_BODY_LEN}")
    # 使用零值填充至 CELL_BODY_LEN（tor-spec，body-padding）。
    return header + cell.body.ljust(CELL_BODY_LEN, b"\x00")


def decode(buffer: bytes, version: int) -> tuple[Cell, bytes] | None:
    """从 `buffer` 中提取第一条完整 cell。

    返回 (cell, remaining_bytes)；若缓冲区数据尚不完整则返回 None，
    因为 TLS 数据可能按任意大小的分片到达。
    """
    n = circid_len(version)
    if len(buffer) < n + 1:
        return None
    circ_id = int.from_bytes(buffer[:n], "big")
    command = buffer[n]
    if is_variable_length(command):
        if len(buffer) < n + 3:
            return None
        (length,) = struct.unpack(">H", buffer[n + 1:n + 3])
        end = n + 3 + length
        body_start = n + 3
    else:
        end = n + 1 + CELL_BODY_LEN
        body_start = n + 1
    if len(buffer) < end:
        return None
    return Cell(circ_id, command, buffer[body_start:end]), buffer[end:]


# --- VERSIONS -----------------------------------------------------------------

def versions_cell(versions: list[int]) -> Cell:
    """从两字节大端整数列表构建 VERSIONS cell。"""
    return Cell(0, CellCommand.VERSIONS, b"".join(struct.pack(">H", v) for v in versions))


def negotiate_version(ours: list[int], received_body: bytes) -> int:
    """选择双方共同支持的最高版本（tor-spec，VERSIONS-cells）。"""
    if len(received_body) % 2:
        raise CellError("VERSIONS 消息体字节数不能为奇数")
    theirs = {v for (v,) in struct.iter_unpack(">H", received_body)}
    common = set(ours) & theirs
    if not common:
        raise CellError("双方没有共同支持的链路协议版本")
    return max(common)


# --- DESTROY ------------------------------------------------------------------

DESTROY_REASONS = ["NONE", "PROTOCOL", "INTERNAL", "REQUESTED", "HIBERNATING",
                  "RESOURCELIMIT", "CONNECTFAILED", "OR_IDENTITY", "CHANNEL_CLOSED",
                  "FINISHED", "TIMEOUT", "DESTROYED", "NOSUCHSERVICE"]


def destroy_cell(circ_id: int, reason: int = 0) -> Cell:
    """DESTROY 的消息体只有一个原因码字节；规范推荐 NONE（0）。"""
    if circ_id == 0:
        raise CellError("DESTROY 要求 CircID 不为零")
    return Cell(circ_id, CellCommand.DESTROY, bytes([reason]))


# --- Relay 消息（CGO 之前的传统格式） ----------------------

@dataclass
class RelayMessage:
    command: int
    stream_id: int
    data: bytes = b""
    recognized: int = 0
    digest: bytes = b"\x00\x00\x00\x00"


def encode_relay(msg: RelayMessage, random_bytes=os.urandom) -> bytes:
    """生成 RELAY cell 的 509 字节明文消息体。

    填充方式：四个零字节后接随机字节（tor-spec，relay-cell-padding）。
    摘要另行计算（第 10 章）；本函数直接使用 `msg` 中的摘要值。
    """
    if len(msg.data) > RELAY_DATA_MAX:
        raise CellError(f"每条 cell 最多包含 {RELAY_DATA_MAX} 字节数据")
    header = struct.pack(">BHH4sH", msg.command, msg.recognized,
                               msg.stream_id, msg.digest, len(msg.data))
    space = CELL_BODY_LEN - RELAY_HEADER_LEN - len(msg.data)
    padding = b"\x00" * min(4, space) + random_bytes(max(0, space - 4))
    return header + msg.data + padding


def decode_relay(body: bytes) -> RelayMessage:
    """解析已经解密的 RELAY cell 消息体。"""
    if len(body) != CELL_BODY_LEN:
        raise CellError("RELAY cell 消息体必须为 509 字节")
    command, recognized, stream_id, digest, length = struct.unpack(
        ">BHH4sH", body[:RELAY_HEADER_LEN])
    if length > RELAY_DATA_MAX:
        raise CellError(f"Length 字段 {length} 超过 {RELAY_DATA_MAX}")
    data = body[RELAY_HEADER_LEN:RELAY_HEADER_LEN + length]
    return RelayMessage(command, stream_id, data, recognized, digest)


def describe(cell: Cell, version: int) -> str:
    """生成便于人工阅读的 cell 调试表示。"""
    try:
        name = CellCommand(cell.command).name
    except ValueError:
        name = f"未知命令({cell.command})"
    w = 2 * circid_len(0 if cell.command == CellCommand.VERSIONS else version)
    return f"CircID=0x{cell.circ_id:0{w}x} {name} 消息体={len(cell.body)} 字节"
