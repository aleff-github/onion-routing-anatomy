# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""完整的客户端电路：组合通道、CircID 与分层加密。

整合实验 1–4 的功能，供后续实验使用。
仅可用于本书的私有实验网络。
"""
from __future__ import annotations

import os
import struct

from .channel import Channel, open_channel
from .cells import Cell, CellCommand, RelayCommand, RelayMessage
from .encryption import ClientCircuitCrypto, CellError, Hop
from .laboratory import RelayInfo
from .ntor import (HTYPE_NTOR_V3, CircuitKeys, encode_extensions, create2_body,
                   extend2_body, decode_extensions, hdata_created2,
                   ntor3_client_finish, ntor3_client_start)

MAX_RELAY_EARLY = 8     # MAX_RELAY_EARLY_CELLS_PER_CIRCUIT in tor


class CircuitError(Exception):
    pass


class Circuit:
    def __init__(self, channel: Channel, circ_id: int | None = None):
        self.channel = channel
        # 建立通道的一方使用最高位为 1 的 CircID。
        self.circ_id = (0x80000000 | (int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF)) if circ_id is None else circ_id
        if not isinstance(self.circ_id, int) or not 0x80000000 <= self.circ_id <= 0xFFFFFFFF:
            raise CircuitError("客户端 CircID 无效：最高位必须为 1")
        self.crypto = ClientCircuitCrypto()
        self.relay_early_sent = 0
        self.exit_extensions: list[tuple[int, bytes]] = []
        # 最终跳点发送、但尚未用 SENDME 确认的 DATA cell 数量。
        # 计数属于整个电路，不属于单条流（tor-spec，Circuit-level flow control）。
        self.data_to_ack = 0
        self.sendme_sent = 0

    # --- 发送与接收 relay 消息 -------------------------------
    def send(self, msg: RelayMessage, hop: int | None = None, early: bool = False) -> None:
        """向指定跳点发送消息（默认为最后一跳）。
        early=True 表示使用 EXTEND2 所需的 RELAY_EARLY cell。"""
        command = CellCommand.RELAY_EARLY if early else CellCommand.RELAY
        if early:
            if self.relay_early_sent >= MAX_RELAY_EARLY:
                raise CircuitError("已达到 RELAY_EARLY cell 的数量限制")
            self.relay_early_sent += 1
        self.channel.send(Cell(self.circ_id, command, self.crypto.encrypt(msg, hop)))

    def count_received_data(self) -> None:
        """每收到最终跳点的一条 DATA cell 就调用一次；
        每累计 `sendme_inc` 条就发送一次经过认证的 SENDME（版本 1）。"""
        # 同一扩展出现多次时，仅采用第一次出现的值（tor-spec）。
        response_data = next((data for kind, data in self.exit_extensions if kind == 2), None)
        sendme_inc = 100 if response_data is None else (response_data[0] if len(response_data) == 1 else 0)
        if sendme_inc is None or sendme_inc == 0:
            raise CircuitError("拥塞控制响应中的 sendme_inc 值无效")
        self.data_to_ack += 1
        if self.data_to_ack == sendme_inc:
            # 摘要来自触发 SENDME 的已识别 cell 处理完成之后的运行状态：
            # 参见 src/core/crypto/relay_crypto_tor1.c 的 sendme_digest。
            digest = self.crypto.hops[-1].backward.digest.digest()
            body = struct.pack(">BH", 1, 20) + digest
            self.send(RelayMessage(RelayCommand.SENDME, 0, body))
            self.data_to_ack = 0
            self.sendme_sent += 1

    def receive(self) -> tuple[int, RelayMessage]:
        """等待本电路的下一条 relay 消息（忽略填充）。"""
        while True:
            cell = self.channel.receive()
            if cell.command in (CellCommand.PADDING, CellCommand.VPADDING):
                continue
            if cell.circ_id != self.circ_id:
                continue                                  # 同一通道上的其他电路
            if cell.command == CellCommand.DESTROY:
                if not cell.body:
                    raise CircuitError("DESTROY 信元缺少原因码")
                raise CircuitError(f"电路已被销毁，原因码 {cell.body[0]}")
            if cell.command != CellCommand.RELAY:
                raise CircuitError(f"意外的 cell {cell.command}")
            return self.crypto.decrypt(cell.body)

    # --- 电路构建 ---------------------------------------------------------
    def create(self, r: RelayInfo, extensions=()) -> list[tuple[int, bytes]]:
        st, hd = ntor3_client_start(r.id_ed, r.ntor, encode_extensions(list(extensions)))
        self.channel.send(Cell(self.circ_id, CellCommand.CREATE2, create2_body(HTYPE_NTOR_V3, hd)))
        response = self.channel.receive()
        while response.command in (CellCommand.PADDING, CellCommand.VPADDING):
            response = self.channel.receive()
        if response.circ_id != self.circ_id:
            raise CircuitError("CREATED2 的 CircID 与请求的电路不一致")
        if response.command != CellCommand.CREATED2:
            raise CircuitError(f"CREATE2 被拒绝（命令 {response.command}）")
        sm, k = ntor3_client_finish(st, hdata_created2(response.body))
        received_extensions = decode_extensions(sm)
        self.crypto.hops.append(Hop.from_keys(CircuitKeys.from_stream(k)))
        return received_extensions

    def extend(self, r: RelayInfo, extensions=()) -> list[tuple[int, bytes]]:
        st, hd = ntor3_client_start(r.id_ed, r.ntor, encode_extensions(list(extensions)))
        body = extend2_body("127.0.0.1", r.port, r.id_rsa, r.id_ed, HTYPE_NTOR_V3, hd)
        self.send(RelayMessage(RelayCommand.EXTEND2, 0, body), early=True)
        hop, msg = self.receive()
        if hop != len(self.crypto.hops) - 1:
            raise CircuitError("EXTENDED2 来自非预期的跳点")
        if msg.command != RelayCommand.EXTENDED2:
            name = RelayCommand._value2member_map_.get(msg.command)
            raise CircuitError(f"电路扩展失败: {name.name if name else msg.command}")
        sm, k = ntor3_client_finish(st, hdata_created2(msg.data))
        received_extensions = decode_extensions(sm)
        self.crypto.hops.append(Hop.from_keys(CircuitKeys.from_stream(k)))
        return received_extensions


def build(path: list[RelayInfo], cc: bool = True) -> Circuit:
    """打开到第一台中继的通道，沿完整路径逐跳构建电路。
    cc=True 时按照 tor 的方式向最后一跳请求拥塞控制。"""
    if not path:
        raise CircuitError("不能使用空路径建立电路")
    guard = path[0]
    channel = open_channel("127.0.0.1", guard.port, expected_identity=guard.id_ed)
    try:
        circ = Circuit(channel)
        last = len(path) - 1
        for i, r in enumerate(path):
            est = [(1, b"")] if (cc and i == last) else []
            response = circ.create(r, est) if i == 0 else circ.extend(r, est)
            if i == last:
                circ.exit_extensions = response
    except BaseException:
        channel.sock.close()
        raise
    return circ
