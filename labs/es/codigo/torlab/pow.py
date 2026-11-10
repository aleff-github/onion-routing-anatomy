# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 9 — capa de aceptación Blake2b del PoW de servicios onion.

Esta es únicamente una simulación estadística didáctica. Los candidatos aleatorios
de 16 bytes NO son soluciones Equi-X; su aceptación NO demuestra un PoW Tor válido.
La verificación real requiere Equi-X, descriptores autenticados, semillas vigentes y
protección contra reutilización del nonce (hspow-spec, esquema v1).
"""
from __future__ import annotations

import hashlib
import os
import struct

P_STRING = b"Tor hs intro v1\x00"  # Personalización de Tor v1; los bytes del protocolo no se traducen
UINT32_MAX = 2 ** 32 - 1
UINT128_MAX = 2 ** 128 - 1


def _fixed_bytes(value: bytes, length: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{label} debe tener exactamente {length} bytes")


def _effort(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MAX:
        raise ValueError("debe ser un entero sin signo de 32 bits")


def check_value(service_id: bytes, seed: bytes, nonce: bytes, effort: int,
                solution: bytes) -> int:
    """Calcula R: BLAKE2b-32(P | ID | C | N | E | S) como entero big-endian."""
    _fixed_bytes(service_id, 32, "identidad cegada del servicio")
    _fixed_bytes(seed, 32, "semilla PoW")
    _fixed_bytes(nonce, 16, "nonce PoW")
    _fixed_bytes(solution, 16, "bytes de la prueba Equi-X")
    _effort(effort)
    challenge = P_STRING + service_id + seed + nonce + struct.pack(">I", effort)
    # BLAKE2b-32 usa digest_size=4, no los cuatro primeros bytes de BLAKE2b-512.
    return int.from_bytes(hashlib.blake2b(challenge + solution, digest_size=4).digest(), "big")


def valid_effort(r: int, effort: int) -> bool:
    """Comprueba R × E <= 2^32 - 1; no valida por sí sola una prueba Equi-X."""
    if isinstance(r, bool) or not isinstance(r, int) or not 0 <= r <= UINT32_MAX:
        raise ValueError("R debe ser un entero sin signo de 32 bits")
    _effort(effort)
    return r * effort <= UINT32_MAX


def _increment_nonce(nonce: bytes) -> bytes:
    """Incrementa un nonce de 16 bytes little-endian módulo 2^128."""
    _fixed_bytes(nonce, 16, "nonce PoW")
    return ((int.from_bytes(nonce, "little") + 1) & UINT128_MAX).to_bytes(16, "little")


def required_attempts(effort: int, service_id: bytes, seed: bytes,
                       max_attempts: int = 10000) -> int:
    """Prueba como máximo max_attempts candidatos simulados; no resuelve Equi-X."""
    _effort(effort)
    _fixed_bytes(service_id, 32, "identidad cegada del servicio")
    _fixed_bytes(seed, 32, "semilla PoW")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts debe ser un entero positivo")
    nonce = os.urandom(16)
    for attempts in range(1, max_attempts + 1):
        candidate = os.urandom(16)  # Solo una aproximación estadística, NO una solución Equi-X.
        if valid_effort(check_value(service_id, seed, nonce, effort, candidate), effort):
            return attempts
        nonce = _increment_nonce(nonce)
    raise RuntimeError("no se encontró un candidato simulado en max_attempts intentos")
