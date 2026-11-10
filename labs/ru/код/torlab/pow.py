# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 9 — проверка Blake2b в PoW onion-сервисов.

Это только статистическая учебная симуляция. Случайные кандидаты из 16 байт
НЕ являются решениями Equi-X, а успешная проверка НЕ означает допустимый PoW Tor.
Настоящая проверка требует Equi-X, доверенных дескрипторов, срока seed и защиты
от повторного использования nonce (hspow-spec, схема v1).
"""
from __future__ import annotations

import hashlib
import os
import struct

P_STRING = b"Tor hs intro v1\x00"  # Строка персонализации Tor v1; байты протокола не переводятся
UINT32_MAX = 2 ** 32 - 1
UINT128_MAX = 2 ** 128 - 1


def _fixed_bytes(value: bytes, length: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{label} должно содержать ровно {length} байт")


def _effort(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MAX:
        raise ValueError("должно быть беззнаковым 32-битным целым")


def check_value(service_id: bytes, seed: bytes, nonce: bytes, effort: int,
                solution: bytes) -> int:
    """Вычисляет R: BLAKE2b-32(P | ID | C | N | E | S) как число big-endian."""
    _fixed_bytes(service_id, 32, "ослеплённый идентификатор сервиса")
    _fixed_bytes(seed, 32, "seed для PoW")
    _fixed_bytes(nonce, 16, "nonce для PoW")
    _fixed_bytes(solution, 16, "байты доказательства Equi-X")
    _effort(effort)
    challenge = P_STRING + service_id + seed + nonce + struct.pack(">I", effort)
    # BLAKE2b-32 использует digest_size=4, а не первые 4 байта BLAKE2b-512.
    return int.from_bytes(hashlib.blake2b(challenge + solution, digest_size=4).digest(), "big")


def valid_effort(r: int, effort: int) -> bool:
    """Проверяет R × E <= 2^32 - 1; этого недостаточно для проверки Equi-X."""
    if isinstance(r, bool) or not isinstance(r, int) or not 0 <= r <= UINT32_MAX:
        raise ValueError("R должно быть беззнаковым 32-битным целым")
    _effort(effort)
    return r * effort <= UINT32_MAX


def _increment_nonce(nonce: bytes) -> bytes:
    """Увеличивает 16-байтовый nonce little-endian по модулю 2^128."""
    _fixed_bytes(nonce, 16, "nonce для PoW")
    return ((int.from_bytes(nonce, "little") + 1) & UINT128_MAX).to_bytes(16, "little")


def required_attempts(effort: int, service_id: bytes, seed: bytes,
                       max_attempts: int = 10000) -> int:
    """Проверяет не более max_attempts случайных кандидатов, без настоящего Equi-X."""
    _effort(effort)
    _fixed_bytes(service_id, 32, "ослеплённый идентификатор сервиса")
    _fixed_bytes(seed, 32, "seed для PoW")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts должно быть положительным целым")
    nonce = os.urandom(16)
    for attempts in range(1, max_attempts + 1):
        candidate = os.urandom(16)  # Статистическая подстановка, НЕ решение Equi-X.
        if valid_effort(check_value(service_id, seed, nonce, effort, candidate), effort):
            return attempts
        nonce = _increment_nonce(nonce)
    raise RuntimeError("подходящий кандидат не найден за max_attempts попыток")
