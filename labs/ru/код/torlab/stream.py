# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 5 — потоки и управление потоком.

Источники: tor-spec, "Opening streams and transmitting data", "Closing streams",
"Flow control"; proposal 324 (congestion control, SENDME и XON/XOFF).
Цепь согласовала управление перегрузкой с exit: на уровне потока сообщений SENDME нет;
исходящие SENDME цепи формируются методом Circuit.count_received_data().
Учебный модуль: использовать только в приватной лабораторной сети книги.
Учебная модель одного потока: нет мультиплексирования, проверки входящих
SENDME цепи и окна отправки; это не полнофункциональный клиент Tor.
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
    """ASCII ADDRPORT с NUL; FLAGS необязателен (только биты 1–3)."""
    if not isinstance(address, str) or not address or "\x00" in address:
        raise ValueError("Адрес должен быть непустой строкой без NUL")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in address):
        raise ValueError("Адрес не должен содержать пробелы и управляющие символы")
    try:
        address.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("ADDRPORT должен быть ASCII (международные домены кодировать через IDNA)") from exc
    if ":" in address or "[" in address or "]" in address:
        if not (address.startswith("[") and address.endswith("]")):
            raise ValueError("IPv6-адрес нужно заключить в квадратные скобки")
        try:
            ipaddress.IPv6Address(address[1:-1])
        except ValueError as exc:
            raise ValueError("Некорректный IPv6-адрес") from exc
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Порт должен быть целым числом от 1 до 65535")
    if type(flag) is not int or not 0 <= flag <= 7:
        raise ValueError("FLAGS допускает только биты 1–3")
    body = f"{address.lower()}:{port}".encode("ascii") + b"\x00"
    if flag:
        body += struct.pack(">I", flag)
    if len(body) > RELAY_DATA_MAX:
        raise ValueError("Тело BEGIN превышает максимальный размер relay")
    return body


def _end_reason(data: bytes) -> str:
    reason = data[0] if data else 1   # Пустой RELAY_END означает REASON_MISC.
    return END_REASONS.get(reason, f"НЕИЗВЕСТНО({reason})")


@dataclass
class StreamRegistry:
    received_data: int = 0
    data_cells: int = 0
    others: list[str] = field(default_factory=list)


class Stream:
    def __init__(self, circ: Circuit, stream_id: int):
        if type(stream_id) is not int or not 1 <= stream_id <= 65535:
            raise CircuitError("StreamID должен быть ненулевым 16-битным целым числом")
        self.circ, self.id = circ, stream_id
        self.reg = StreamRegistry()
        self.closed = False
        self.opened = False

    def open(self, address: str, port: int) -> bytes:
        if self.closed or self.opened:
            raise CircuitError("поток уже открыт или закрыт")
        self.circ.send(RelayMessage(RelayCommand.BEGIN, self.id, begin_body(address, port)))
        while True:
            _, msg = self._next()
            if msg.command == RelayCommand.DROP:
                continue
            if msg.command == RelayCommand.END:
                self.closed = True
                raise CircuitError(f"BEGIN отклонён: {_end_reason(msg.data)}")
            if msg.command != RelayCommand.CONNECTED:
                raise CircuitError(f"неожиданный ответ на BEGIN: {msg.command}")
            self.opened = True
            return msg.data

    def send(self, data: bytes) -> None:
        if self.closed or not self.opened:
            raise CircuitError("нельзя отправлять данные в неоткрытый или закрытый поток")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("данные должны быть байтовым объектом")
        data = bytes(data)
        for i in range(0, len(data), RELAY_DATA_MAX):
            self.circ.send(RelayMessage(RelayCommand.DATA, self.id, data[i:i + RELAY_DATA_MAX]))

    def receive_all(self) -> bytes:
        """Читать DATA до END, учитывая исходящие SENDME цепи."""
        if not self.opened:
            raise CircuitError("поток не открыт")
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
                self.reg.others.append(known.name if known else f"НЕИЗВЕСТНО_{msg.command}")
        return b"".join(parts)

    def _next(self):
        hop, msg = self.circ.receive()
        if msg.stream_id == 0:
            if msg.command == RelayCommand.DROP:
                return hop, msg
            if msg.command == RelayCommand.SENDME:
                # Нельзя принимать входящий SENDME без проверки окна и дайджеста.
                raise CircuitError("входящий SENDME цепи: окно отправки и проверка дайджеста не реализованы")
            raise CircuitError(f"неожиданная команда управления цепью: {msg.command}")
        if msg.stream_id != self.id:
            raise CircuitError(f"сообщение для неизвестного потока {msg.stream_id}")
        return hop, msg

    def close(self) -> None:
        if not self.closed:
            if not self.opened:
                raise CircuitError("поток не открыт")
            self.circ.send(RelayMessage(RelayCommand.END, self.id, bytes([6])))  # DONE
            self.closed = True
