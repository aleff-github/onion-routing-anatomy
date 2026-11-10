# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 4 — луковичная модель: шифрование ячеек RELAY по tor1.

Источники: tor-spec, «Relay cells» (Recognized, Digest) и «Routing relay cells».
У каждого узла в каждом направлении свой AES-128-CTR и накапливаемый SHA-1;
оба состояния сохраняются между последовательными ячейками.
Учебный модуль: применять исключительно в закрытой лабораторной сети книги.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .cells import CELL_BODY_LEN, RelayMessage, encode_relay, decode_relay
from .ntor import CircuitKeys

POS_DIGEST = slice(5, 9)       # байты поля Digest в незашифрованном теле
POS_RECOGNIZED = slice(1, 3)


def _aes_ctr(key: bytes):
    # Нулевой IV: счётчик продолжается от ячейки к ячейке всю жизнь цепочки.
    return Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()


def _without_digest(body: bytes) -> bytes:
    return body[:5] + bytes(4) + body[9:]


@dataclass
class Direction:
    """Состояние одного направления одного узла: поток AES и накапливаемый дайджест."""
    cipher: object
    digest: "hashlib._Hash"

    @classmethod
    def new(cls, key: bytes, digest_seed: bytes) -> "Direction":
        if len(key) != 16 or len(digest_seed) != 20:
            raise CellError("для AES-128 требуется ключ из 16 байт и начальное значение дайджеста из 20 байт")
        d = hashlib.sha1()
        d.update(digest_seed)
        return cls(_aes_ctr(key), d)

    def apply(self, data: bytes) -> bytes:
        """В режиме CTR шифрование и расшифрование сводятся к XOR с потоком ключа."""
        if len(data) != CELL_BODY_LEN:
            raise CellError("тело ячейки RELAY tor1 должно содержать ровно 509 байт")
        return self.cipher.update(data)

    def sign(self, body: bytes) -> bytes:
        """Обновить дайджест по ячейке с нулевым полем Digest и записать первые четыре байта."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("тело ячейки RELAY tor1 должно содержать ровно 509 байт")
        self.digest.update(_without_digest(body))
        return body[:5] + self.digest.digest()[:4] + body[9:]

    def recognizes(self, body: bytes) -> bool:
        """Recognized равен нулю и дайджест верен; обновлять состояние только для ячейки этого узла."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("тело ячейки RELAY tor1 должно содержать ровно 509 байт")
        if body[POS_RECOGNIZED] != b"\x00\x00":
            return False
        candidate = self.digest.copy()
        candidate.update(_without_digest(body))
        if not hmac.compare_digest(candidate.digest()[:4], body[POS_DIGEST]):
            return False                      # ложное совпадение поля Recognized: проигнорировать
        self.digest = candidate
        return True


@dataclass
class Hop:
    """Состояние, общее для клиента и ретранслятора одного узла цепочки."""
    forward: Direction
    backward: Direction

    @classmethod
    def from_keys(cls, k: CircuitKeys) -> "Hop":
        return cls(Direction.new(k.Kf, k.Df), Direction.new(k.Kb, k.Db))


class CellError(Exception):
    pass


@dataclass
class ClientCircuitCrypto:
    """Сторона клиента: знает ключи каждого узла цепочки."""
    hops: list[Hop] = field(default_factory=list)

    def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
        """Подготовить тело ячейки RELAY для узла `destination` (0 — первый)."""
        if not self.hops:
            raise CellError("в цепочке нет узлов")
        d = len(self.hops) - 1 if destination is None else destination
        if not isinstance(d, int) or not 0 <= d < len(self.hops):
            raise CellError("недопустимый индекс узла назначения")
        body = self.hops[d].forward.sign(encode_relay(msg))
        for i in range(d, -1, -1):             # шифровать от внутреннего слоя к внешнему
            body = self.hops[i].forward.apply(body)
        return body

    def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
        """Снимать слои входящей ячейки, пока один из узлов её не распознает."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("тело ячейки RELAY tor1 должно содержать ровно 509 байт")
        if not self.hops:
            raise CellError("в цепочке нет узлов")
        for i, hop in enumerate(self.hops):
            body = hop.backward.apply(body)
            if hop.backward.recognizes(body):
                return i, decode_relay(body)
        raise CellError("ячейка не распознана ни одним узлом: цепочку следует закрыть")


@dataclass
class RelayHop:
    """Сторона ретранслятора (для тестов): знает ключи только собственного узла."""
    hop: Hop

    def from_client(self, body: bytes) -> tuple[bool, bytes]:
        body = self.hop.forward.apply(body)
        return self.hop.forward.recognizes(body), body

    def to_client(self, msg: RelayMessage) -> bytes:
        return self.hop.backward.apply(self.hop.backward.sign(encode_relay(msg)))

    def forward_to_client(self, body: bytes) -> bytes:
        return self.hop.backward.apply(body)
