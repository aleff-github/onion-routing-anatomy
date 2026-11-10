# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Circuito completo del cliente: canal, CircID y cifrado por capas.

Combina los laboratorios 1–4 en una clase reutilizada por los siguientes.
Módulo didáctico: utilizar solo en la red privada del libro.
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

MAX_RELAY_EARLY = 8     # MAX_RELAY_EARLY_CELLS_PER_CIRCUIT en tor


class CircuitError(Exception):
    pass


class Circuit:
    def __init__(self, channel: Channel, circ_id: int | None = None):
        self.channel = channel
        # Quien abre el canal utiliza CircID con el bit más significativo activado.
        self.circ_id = (0x80000000 | (int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF)) if circ_id is None else circ_id
        if not isinstance(self.circ_id, int) or not 0x80000000 <= self.circ_id <= 0xFFFFFFFF:
            raise CircuitError("CircID de cliente inválido: el bit más significativo debe ser uno")
        self.crypto = ClientCircuitCrypto()
        self.relay_early_sent = 0
        self.exit_extensions: list[tuple[int, bytes]] = []
        # Celdas DATA del último salto pendientes de confirmación con SENDME.
        # El contador corresponde al circuito, no al flujo (tor-spec, control de flujo).
        self.data_to_ack = 0
        self.sendme_sent = 0

    # --- Envío y recepción de mensajes relay -------------------------------
    def send(self, msg: RelayMessage, hop: int | None = None, early: bool = False) -> None:
        """Envía un mensaje al salto indicado (por defecto, el último).
        early=True utiliza una celda RELAY_EARLY, obligatoria para EXTEND2."""
        command = CellCommand.RELAY_EARLY if early else CellCommand.RELAY
        if early:
            if self.relay_early_sent >= MAX_RELAY_EARLY:
                raise CircuitError("límite de celdas RELAY_EARLY alcanzado")
            self.relay_early_sent += 1
        self.channel.send(Cell(self.circ_id, command, self.crypto.encrypt(msg, hop)))

    def count_received_data(self) -> None:
        """Llamar por cada celda DATA recibida del último salto: enviar un SENDME
        autenticado (versión 1) cada `sendme_inc` celdas."""
        # Si una extensión se repite, solo cuenta la primera aparición (tor-spec).
        response_data = next((data for kind, data in self.exit_extensions if kind == 2), None)
        sendme_inc = 100 if response_data is None else (response_data[0] if len(response_data) == 1 else 0)
        if sendme_inc is None or sendme_inc == 0:
            raise CircuitError("parámetro sendme_inc de control de congestión inválido")
        self.data_to_ack += 1
        if self.data_to_ack == sendme_inc:
            # Digest acumulativo tras la celda reconocida que provoca SENDME:
            # sendme_digest en src/core/crypto/relay_crypto_tor1.c.
            digest = self.crypto.hops[-1].backward.digest.digest()
            body = struct.pack(">BH", 1, 20) + digest
            self.send(RelayMessage(RelayCommand.SENDME, 0, body))
            self.data_to_ack = 0
            self.sendme_sent += 1

    def receive(self) -> tuple[int, RelayMessage]:
        """Espera el siguiente mensaje relay del circuito (ignora el relleno)."""
        while True:
            cell = self.channel.receive()
            if cell.command in (CellCommand.PADDING, CellCommand.VPADDING):
                continue
            if cell.circ_id != self.circ_id:
                continue                                  # otros circuitos del mismo canal
            if cell.command == CellCommand.DESTROY:
                if not cell.body:
                    raise CircuitError("celda DESTROY sin código de motivo")
                raise CircuitError(f"circuito destruido, motivo {cell.body[0]}")
            if cell.command != CellCommand.RELAY:
                raise CircuitError(f"celda inesperada {cell.command}")
            return self.crypto.decrypt(cell.body)

    # --- Construcción del circuito ---------------------------------------------------------
    def create(self, r: RelayInfo, extensions=()) -> list[tuple[int, bytes]]:
        st, hd = ntor3_client_start(r.id_ed, r.ntor, encode_extensions(list(extensions)))
        self.channel.send(Cell(self.circ_id, CellCommand.CREATE2, create2_body(HTYPE_NTOR_V3, hd)))
        response = self.channel.receive()
        while response.command in (CellCommand.PADDING, CellCommand.VPADDING):
            response = self.channel.receive()
        if response.circ_id != self.circ_id:
            raise CircuitError("el CircID de CREATED2 no corresponde al circuito solicitado")
        if response.command != CellCommand.CREATED2:
            raise CircuitError(f"CREATE2 rechazado (comando {response.command})")
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
            raise CircuitError("EXTENDED2 procede de un salto inesperado")
        if msg.command != RelayCommand.EXTENDED2:
            name = RelayCommand._value2member_map_.get(msg.command)
            raise CircuitError(f"fallo de ampliación: {name.name if name else msg.command}")
        sm, k = ntor3_client_finish(st, hdata_created2(msg.data))
        received_extensions = decode_extensions(sm)
        self.crypto.hops.append(Hop.from_keys(CircuitKeys.from_stream(k)))
        return received_extensions


def build(path: list[RelayInfo], cc: bool = True) -> Circuit:
    """Abre un canal hacia el primer repetidor y construye el circuito completo.
    Con cc=True solicita control de congestión al último salto, como tor."""
    if not path:
        raise CircuitError("no se puede construir un circuito a partir de una ruta vacía")
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
