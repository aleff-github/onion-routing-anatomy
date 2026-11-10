# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 5 — flujos y control de flujo.

Referencias: tor-spec, apertura y cierre de flujos, transmisión de datos y
control de flujo; propuesta 324 (control de congestión, SENDME y XON/XOFF).
El circuito ha negociado el control de congestión con la salida: no hay SENDME
por flujo; Circuit.count_received_data() genera los SENDME salientes del circuito.
Módulo didáctico: utilizar solo en la red privada del libro.
Modelo didáctico de un solo flujo: sin multiplexación, verificación de SENDME
entrantes del circuito ni control de la ventana de envío; no es un cliente Tor completo.
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
    """ADDRPORT ASCII terminado en NUL; FLAGS opcional (solo bits 1–3)."""
    if not isinstance(address, str) or not address or "\x00" in address:
        raise ValueError("La dirección debe ser texto no vacío y sin NUL")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in address):
        raise ValueError("La dirección no puede contener espacios ni caracteres de control")
    try:
        address.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("ADDRPORT debe ser ASCII (codifique los dominios internacionales con IDNA)") from exc
    if ":" in address or "[" in address or "]" in address:
        if not (address.startswith("[") and address.endswith("]")):
            raise ValueError("Las direcciones IPv6 deben ir entre corchetes")
        try:
            ipaddress.IPv6Address(address[1:-1])
        except ValueError as exc:
            raise ValueError("Dirección IPv6 no válida") from exc
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("El puerto debe ser un entero de 1 a 65535")
    if type(flag) is not int or not 0 <= flag <= 7:
        raise ValueError("FLAGS solo puede usar los bits 1–3")
    body = f"{address.lower()}:{port}".encode("ascii") + b"\x00"
    if flag:
        body += struct.pack(">I", flag)
    if len(body) > RELAY_DATA_MAX:
        raise ValueError("El cuerpo BEGIN supera la carga útil máxima de relay")
    return body


def _end_reason(data: bytes) -> str:
    reason = data[0] if data else 1   # Un RELAY_END vacío equivale a REASON_MISC.
    return END_REASONS.get(reason, f"DESCONOCIDO({reason})")


@dataclass
class StreamRegistry:
    received_data: int = 0
    data_cells: int = 0
    others: list[str] = field(default_factory=list)


class Stream:
    def __init__(self, circ: Circuit, stream_id: int):
        if type(stream_id) is not int or not 1 <= stream_id <= 65535:
            raise CircuitError("StreamID debe ser un entero no nulo de 16 bits")
        self.circ, self.id = circ, stream_id
        self.reg = StreamRegistry()
        self.closed = False
        self.opened = False

    def open(self, address: str, port: int) -> bytes:
        if self.closed or self.opened:
            raise CircuitError("el flujo ya está abierto o cerrado")
        self.circ.send(RelayMessage(RelayCommand.BEGIN, self.id, begin_body(address, port)))
        while True:
            _, msg = self._next()
            if msg.command == RelayCommand.DROP:
                continue
            if msg.command == RelayCommand.END:
                self.closed = True
                raise CircuitError(f"BEGIN rechazado: {_end_reason(msg.data)}")
            if msg.command != RelayCommand.CONNECTED:
                raise CircuitError(f"respuesta inesperada a BEGIN: {msg.command}")
            self.opened = True
            return msg.data

    def send(self, data: bytes) -> None:
        if self.closed or not self.opened:
            raise CircuitError("no se pueden enviar datos en un flujo no abierto o cerrado")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("los datos deben ser de tipo bytes")
        data = bytes(data)
        for i in range(0, len(data), RELAY_DATA_MAX):
            self.circ.send(RelayMessage(RelayCommand.DATA, self.id, data[i:i + RELAY_DATA_MAX]))

    def receive_all(self) -> bytes:
        """Lee DATA hasta END y contabiliza los SENDME salientes del circuito."""
        if not self.opened:
            raise CircuitError("el flujo aún no está abierto")
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
                self.reg.others.append(known.name if known else f"DESCONOCIDO_{msg.command}")
        return b"".join(parts)

    def _next(self):
        hop, msg = self.circ.receive()
        if msg.stream_id == 0:
            if msg.command == RelayCommand.DROP:
                return hop, msg
            if msg.command == RelayCommand.SENDME:
                # No aceptar SENDME entrantes sin verificar la ventana y el resumen.
                raise CircuitError("SENDME entrante de circuito: sin gestión de ventana ni verificación de resumen")
            raise CircuitError(f"comando de control de circuito inesperado: {msg.command}")
        if msg.stream_id != self.id:
            raise CircuitError(f"mensaje destinado a un flujo desconocido {msg.stream_id}")
        return hop, msg

    def close(self) -> None:
        if not self.closed:
            if not self.opened:
                raise CircuitError("el flujo aún no está abierto")
            self.circ.send(RelayMessage(RelayCommand.END, self.id, bytes([6])))  # DONE
            self.closed = True
