# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 9 — strato di accettazione Blake2b del PoW degli onion service.

Questa è soltanto una simulazione statistica didattica. I candidati casuali di
16 byte NON sono soluzioni Equi-X: superare la soglia NON dimostra un PoW Tor valido.
La verifica reale richiede Equi-X, descrittori autenticati, semi validi e protezione
contro il riuso dei nonce (hspow-spec, schema v1).
"""
from __future__ import annotations

import hashlib
import os
import struct

P_STRING = b"Tor hs intro v1\x00"  # Stringa di personalizzazione Tor v1; i byte del protocollo non si traducono
UINT32_MAX = 2 ** 32 - 1
UINT128_MAX = 2 ** 128 - 1


def _fixed_bytes(value: bytes, length: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{label} deve contenere esattamente {length} byte")


def _effort(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MAX:
        raise ValueError("deve essere un intero senza segno a 32 bit")


def valore_controllo(id_servizio: bytes, seme: bytes, nonce: bytes, sforzo: int,
                soluzione: bytes) -> int:
    """Calcola R: BLAKE2b-32(P | ID | C | N | E | S) come intero big-endian."""
    _fixed_bytes(id_servizio, 32, "identità accecata del servizio")
    _fixed_bytes(seme, 32, "seme del PoW")
    _fixed_bytes(nonce, 16, "nonce del PoW")
    _fixed_bytes(soluzione, 16, "byte della prova Equi-X")
    _effort(sforzo)
    challenge = P_STRING + id_servizio + seme + nonce + struct.pack(">I", sforzo)
    # BLAKE2b-32 usa digest_size=4, non i primi quattro byte di BLAKE2b-512.
    return int.from_bytes(hashlib.blake2b(challenge + soluzione, digest_size=4).digest(), "big")


def sforzo_valido(r: int, sforzo: int) -> bool:
    """Verifica R × E <= 2^32 - 1; da sola non convalida una prova Equi-X."""
    if isinstance(r, bool) or not isinstance(r, int) or not 0 <= r <= UINT32_MAX:
        raise ValueError("R deve essere un intero senza segno a 32 bit")
    _effort(sforzo)
    return r * sforzo <= UINT32_MAX


def _increment_nonce(nonce: bytes) -> bytes:
    """Incrementa il nonce little-endian di 16 byte modulo 2^128."""
    _fixed_bytes(nonce, 16, "nonce del PoW")
    return ((int.from_bytes(nonce, "little") + 1) & UINT128_MAX).to_bytes(16, "little")


def tentativi_necessari(sforzo: int, id_servizio: bytes, seme: bytes,
                       max_attempts: int = 10000) -> int:
    """Prova al massimo max_attempts candidati simulati, senza calcolare Equi-X."""
    _effort(sforzo)
    _fixed_bytes(id_servizio, 32, "identità accecata del servizio")
    _fixed_bytes(seme, 32, "seme del PoW")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts deve essere un intero positivo")
    nonce = os.urandom(16)
    for attempts in range(1, max_attempts + 1):
        candidate = os.urandom(16)  # Sostituto statistico, NON una soluzione Equi-X.
        if sforzo_valido(valore_controllo(id_servizio, seme, nonce, sforzo, candidate), sforzo):
            return attempts
        nonce = _increment_nonce(nonce)
    raise RuntimeError("nessun candidato simulato trovato entro max_attempts tentativi")
