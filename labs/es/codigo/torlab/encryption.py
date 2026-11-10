# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 4 — cifrado por capas tor1 de las celdas relay.

Referencias: tor-spec, celdas relay (Recognized, Digest) y su enrutamiento.
Cada salto mantiene un cifrador AES-128-CTR y un digest SHA-1 acumulativo por dirección;
ambos conservan su estado entre celdas.
Módulo didáctico: usar exclusivamente en la red privada del libro.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .cells import CELL_BODY_LEN, RelayMessage, encode_relay, decode_relay
from .ntor import CircuitKeys

POS_DIGEST = slice(5, 9)       # bytes del campo Digest en el cuerpo sin cifrar
POS_RECOGNIZED = slice(1, 3)


def _aes_ctr(key: bytes):
    # IV cero: el contador continúa entre celdas durante toda la vida del circuito.
    return Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()


def _without_digest(body: bytes) -> bytes:
    return body[:5] + bytes(4) + body[9:]


@dataclass
class Direction:
    """Estado de una dirección de un salto: flujo AES y digest acumulativo."""
    cipher: object
    digest: "hashlib._Hash"

    @classmethod
    def new(cls, key: bytes, digest_seed: bytes) -> "Direction":
        if len(key) != 16 or len(digest_seed) != 20:
            raise CellError("AES-128 requiere una clave de 16 bytes y una semilla de digest de 20 bytes")
        d = hashlib.sha1()
        d.update(digest_seed)
        return cls(_aes_ctr(key), d)

    def apply(self, data: bytes) -> bytes:
        """Cifrar y descifrar en CTR equivale a aplicar XOR con el flujo de claves."""
        if len(data) != CELL_BODY_LEN:
            raise CellError("el cuerpo de una celda RELAY tor1 debe tener exactamente 509 bytes")
        return self.cipher.update(data)

    def sign(self, body: bytes) -> bytes:
        """Actualiza el digest con la celda (Digest a cero) y escribe los primeros 4 bytes."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("el cuerpo de una celda RELAY tor1 debe tener exactamente 509 bytes")
        self.digest.update(_without_digest(body))
        return body[:5] + self.digest.digest()[:4] + body[9:]

    def recognizes(self, body: bytes) -> bool:
        """Recognized vale cero y el digest coincide; actualizar solo si este salto recibe la celda."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("el cuerpo de una celda RELAY tor1 debe tener exactamente 509 bytes")
        if body[POS_RECOGNIZED] != b"\x00\x00":
            return False
        candidate = self.digest.copy()
        candidate.update(_without_digest(body))
        if not hmac.compare_digest(candidate.digest()[:4], body[POS_DIGEST]):
            return False                      # falso positivo de Recognized: ignorar
        self.digest = candidate
        return True


@dataclass
class Hop:
    """Estado compartido por cliente y repetidor para un salto del circuito."""
    forward: Direction
    backward: Direction

    @classmethod
    def from_keys(cls, k: CircuitKeys) -> "Hop":
        return cls(Direction.new(k.Kf, k.Df), Direction.new(k.Kb, k.Db))


class CellError(Exception):
    pass


@dataclass
class ClientCircuitCrypto:
    """Lado cliente: conoce las claves de todos los saltos."""
    hops: list[Hop] = field(default_factory=list)

    def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
        """Prepara el cuerpo de una celda RELAY para el salto `destination` (0 = primero)."""
        if not self.hops:
            raise CellError("el circuito no contiene saltos")
        d = len(self.hops) - 1 if destination is None else destination
        if not isinstance(d, int) or not 0 <= d < len(self.hops):
            raise CellError("índice de salto de destino no válido")
        body = self.hops[d].forward.sign(encode_relay(msg))
        for i in range(d, -1, -1):             # capas desde la más interna hasta la más externa
            body = self.hops[i].forward.apply(body)
        return body

    def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
        """Retira capas de la celda recibida hasta que un salto la reconozca."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("el cuerpo de una celda RELAY tor1 debe tener exactamente 509 bytes")
        if not self.hops:
            raise CellError("el circuito no contiene saltos")
        for i, hop in enumerate(self.hops):
            body = hop.backward.apply(body)
            if hop.backward.recognizes(body):
                return i, decode_relay(body)
        raise CellError("celda no reconocida por ningún salto: cerrar el circuito")


@dataclass
class RelayHop:
    """Lado repetidor (pruebas): solo conoce las claves de su propio salto."""
    hop: Hop

    def from_client(self, body: bytes) -> tuple[bool, bytes]:
        body = self.hop.forward.apply(body)
        return self.hop.forward.recognizes(body), body

    def to_client(self, msg: RelayMessage) -> bytes:
        return self.hop.backward.apply(self.hop.backward.sign(encode_relay(msg)))

    def forward_to_client(self, body: bytes) -> bytes:
        return self.hop.backward.apply(body)
