# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 5：应用流与流量控制。

规范依据：tor-spec 中 Opening streams and transmitting data、Closing streams、
Flow control，以及第 324 号提案（拥塞控制、SENDME、XON/XOFF）。
此电路已与出口协商拥塞控制，不再使用流级 SENDME；
仅由 Circuit.count_received_data() 生成出站电路 SENDME。
仅允许在本书私有实验网络中运行。
单流教学模型：不支持多路复用、入站电路 SENDME 的身份校验
或发送窗口管理，不能替代完整的 Tor 客户端。
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

from .cells import RELAY_DATA_MAX, RelayCommand, RelayMessage
from .circuit import Circuit, CircuitError

END_REASONS = {1: "MISC", 2: "RESOLVEFAILED", 3: "CONNECTREFUSED", 4: "EXITPOLICY",
              5: "DESTROY", 6: "DONE", 7: "TIMEOUT", 8: "NOROUTE", 9: "HIBERNATING",
              10: "INTERNAL", 11: "RESOURCELIMIT", 12: "CONNRESET", 13: "TORPROTOCOL",
              14: "NOTDIRECTORY"}


def begin_body(address: str, port: int, flag: int = 0) -> bytes:
    """ASCII ADDRPORT 以 NUL 结束；FLAGS 可选（只允许位 1–3）。"""
    if not isinstance(address, str) or not address or "\x00" in address:
        raise ValueError("地址必须是非空字符串且不得包含 NUL")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in address):
        raise ValueError("地址不得包含空格或控制字符")
    try:
        address.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("ADDRPORT 必须是 ASCII（国际化域名请先编码为 IDNA）") from exc
    if ":" in address or "[" in address or "]" in address:
        if not (address.startswith("[") and address.endswith("]")):
            raise ValueError("IPv6 地址必须加方括号")
        try:
            ipaddress.IPv6Address(address[1:-1])
        except ValueError as exc:
            raise ValueError("IPv6 地址无效") from exc
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("端口必须是 1 到 65535 的整数")
    if type(flag) is not int or not 0 <= flag <= 7:
        raise ValueError("FLAGS 只能使用第 1–3 位")
    body = f"{address.lower()}:{port}".encode("ascii") + b"\x00"
    if flag:
        body += struct.pack(">I", flag)
    if len(body) > RELAY_DATA_MAX:
        raise ValueError("BEGIN 数据体超过 relay 最大负载")
    return body


def _end_reason(data: bytes) -> str:
    reason = data[0] if data else 1   # 空的 RELAY_END 等价于 REASON_MISC。
    return END_REASONS.get(reason, f"未知({reason})")


@dataclass
class StreamRegistry:
    received_data: int = 0
    data_cells: int = 0
    others: list[str] = field(default_factory=list)


class Stream:
    def __init__(self, circ: Circuit, stream_id: int):
        if type(stream_id) is not int or not 1 <= stream_id <= 65535:
            raise CircuitError("StreamID 必须是非零的 16 位整数")
        self.circ, self.id = circ, stream_id
        self.reg = StreamRegistry()
        self.closed = False
        self.opened = False

    def open(self, address: str, port: int) -> bytes:
        if self.closed or self.opened:
            raise CircuitError("流已经打开或关闭")
        self.circ.send(RelayMessage(RelayCommand.BEGIN, self.id, begin_body(address, port)))
        while True:
            _, msg = self._next()
            if msg.command == RelayCommand.DROP:
                continue
            if msg.command == RelayCommand.END:
                self.closed = True
                raise CircuitError(f"BEGIN 请求被拒绝: {_end_reason(msg.data)}")
            if msg.command != RelayCommand.CONNECTED:
                raise CircuitError(f"收到意外的 BEGIN 回应: {msg.command}")
            self.opened = True
            return msg.data

    def send(self, data: bytes) -> None:
        if self.closed or not self.opened:
            raise CircuitError("无法向未打开或已关闭的流发送数据")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("数据必须是字节类对象")
        data = bytes(data)
        for i in range(0, len(data), RELAY_DATA_MAX):
            self.circ.send(RelayMessage(RelayCommand.DATA, self.id, data[i:i + RELAY_DATA_MAX]))

    def receive_all(self) -> bytes:
        """读取 DATA 直至 END；统计并按需发送电路级 SENDME。"""
        if not self.opened:
            raise CircuitError("流尚未打开")
        parts = []
        while not self.closed:
            _, msg = self._next()
            if msg.command == RelayCommand.DATA:
                parts.append(msg.data)
                self.reg.received_data += len(msg.data)
                self.reg.data_cells += 1
                self.circ.count_received_data()
            elif msg.command == RelayCommand.END:
                self.closed = True
                self.reg.others.append(f"END {_end_reason(msg.data)}")
            elif msg.command == RelayCommand.DROP:
                continue
            else:
                known = RelayCommand._value2member_map_.get(msg.command)
                self.reg.others.append(known.name if known else f"未知_{msg.command}")
        return b"".join(parts)

    def _next(self):
        hop, msg = self.circ.receive()
        if msg.stream_id == 0:
            if msg.command == RelayCommand.DROP:
                return hop, msg
            if msg.command == RelayCommand.SENDME:
                # 未检查窗口及摘要时不得直接接受入站 SENDME。
                raise CircuitError("收到电路级 SENDME：发送窗口和摘要校验尚未实现")
            raise CircuitError(f"收到非预期的电路控制命令: {msg.command}")
        if msg.stream_id != self.id:
            raise CircuitError(f"收到属于未知流的消息 {msg.stream_id}")
        return hop, msg

    def close(self) -> None:
        if not self.closed:
            if not self.opened:
                raise CircuitError("流尚未打开")
            self.circ.send(RelayMessage(RelayCommand.END, self.id, bytes([6])))  # DONE
            self.closed = True
