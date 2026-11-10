# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Полная клиентская цепочка: канал, CircID и послойное шифрование.

Объединяет лабораторные работы 1–4 в один класс для последующих занятий.
Учебный модуль: использовать только в закрытой лабораторной сети книги.
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

MAX_RELAY_EARLY = 8     # MAX_RELAY_EARLY_CELLS_PER_CIRCUIT в Tor


class CircuitError(Exception):
    pass


class Circuit:
    def __init__(self, channel: Channel, circ_id: int | None = None):
        self.channel = channel
        # Сторона, открывшая канал, использует CircID с установленным старшим битом.
        self.circ_id = (0x80000000 | (int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF)) if circ_id is None else circ_id
        if not isinstance(self.circ_id, int) or not 0x80000000 <= self.circ_id <= 0xFFFFFFFF:
            raise CircuitError("недопустимый CircID клиента: старший бит должен быть равен единице")
        self.crypto = ClientCircuitCrypto()
        self.relay_early_sent = 0
        self.exit_extensions: list[tuple[int, bytes]] = []
        # Ячейки DATA от последнего узла, ещё не подтверждённые через SENDME.
        # Счётчик ведётся для всей цепочки, а не отдельного потока (tor-spec, "Circuit-level flow control").
        self.data_to_ack = 0
        self.sendme_sent = 0

    # --- отправка и приём ретрансляционных сообщений --------------------------------
    def send(self, msg: RelayMessage, hop: int | None = None, early: bool = False) -> None:
        """Отправить сообщение выбранному узлу (по умолчанию последнему).
        early=True использует RELAY_EARLY, обязательную для EXTEND2."""
        command = CellCommand.RELAY_EARLY if early else CellCommand.RELAY
        if early:
            if self.relay_early_sent >= MAX_RELAY_EARLY:
                raise CircuitError("достигнут лимит ячеек RELAY_EARLY")
            self.relay_early_sent += 1
        self.channel.send(Cell(self.circ_id, command, self.crypto.encrypt(msg, hop)))

    def count_received_data(self) -> None:
        """Вызывать для каждой ячейки DATA от последнего узла: отправлять SENDME
        с аутентификацией (версия 1) каждые `sendme_inc` ячеек."""
        # При повторении расширений учитывается только первое (tor-spec).
        response_data = next((data for kind, data in self.exit_extensions if kind == 2), None)
        sendme_inc = 100 if response_data is None else (response_data[0] if len(response_data) == 1 else 0)
        if sendme_inc is None or sendme_inc == 0:
            raise CircuitError("некорректный параметр sendme_inc управления перегрузкой")
        self.data_to_ack += 1
        if self.data_to_ack == sendme_inc:
            # Текущий дайджест после распознанной ячейки, вызвавшей
            # SENDME: sendme_digest в src/core/crypto/relay_crypto_tor1.c.
            digest = self.crypto.hops[-1].backward.digest.digest()
            body = struct.pack(">BH", 1, 20) + digest
            self.send(RelayMessage(RelayCommand.SENDME, 0, body))
            self.data_to_ack = 0
            self.sendme_sent += 1

    def receive(self) -> tuple[int, RelayMessage]:
        """Дождаться следующего ретрансляционного сообщения этой цепочки, игнорируя заполнение."""
        while True:
            cell = self.channel.receive()
            if cell.command in (CellCommand.PADDING, CellCommand.VPADDING):
                continue
            if cell.circ_id != self.circ_id:
                continue                                  # другие цепочки в том же канале
            if cell.command == CellCommand.DESTROY:
                if not cell.body:
                    raise CircuitError("в ячейке DESTROY отсутствует код причины")
                raise CircuitError(f"цепочка уничтожена, причина {cell.body[0]}")
            if cell.command != CellCommand.RELAY:
                raise CircuitError(f"неожиданная ячейка {cell.command}")
            return self.crypto.decrypt(cell.body)

    # --- Построение цепочки -----------------------------------------------------------
    def create(self, r: RelayInfo, extensions=()) -> list[tuple[int, bytes]]:
        st, hd = ntor3_client_start(r.id_ed, r.ntor, encode_extensions(list(extensions)))
        self.channel.send(Cell(self.circ_id, CellCommand.CREATE2, create2_body(HTYPE_NTOR_V3, hd)))
        response = self.channel.receive()
        while response.command in (CellCommand.PADDING, CellCommand.VPADDING):
            response = self.channel.receive()
        if response.circ_id != self.circ_id:
            raise CircuitError("CircID ответа CREATED2 не совпадает с ожидаемым")
        if response.command != CellCommand.CREATED2:
            raise CircuitError(f"CREATE2 отклонена (команда {response.command})")
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
            raise CircuitError("EXTENDED2 поступила не от ожидаемого узла")
        if msg.command != RelayCommand.EXTENDED2:
            name = RelayCommand._value2member_map_.get(msg.command)
            raise CircuitError(f"расширение цепочки не удалось: {name.name if name else msg.command}")
        sm, k = ntor3_client_finish(st, hdata_created2(msg.data))
        received_extensions = decode_extensions(sm)
        self.crypto.hops.append(Hop.from_keys(CircuitKeys.from_stream(k)))
        return received_extensions


def build(path: list[RelayInfo], cc: bool = True) -> Circuit:
    """Открыть канал к первому ретранслятору и построить цепочку по заданному пути.
    При cc=True запросить у последнего узла управление перегрузкой, как в Tor."""
    if not path:
        raise CircuitError("невозможно построить цепочку по пустому маршруту")
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
