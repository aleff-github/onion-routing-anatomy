# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratory 9 — Blake2b acceptance layer of onion-service proof of work.

This is a statistical teaching simulation only. Its random 16-byte candidates are
NOT Equi-X solutions, so acceptance here is NOT a valid Tor proof of work.
Production verification also requires Equi-X, authenticated descriptors, seed validity,
and nonce replay protection (hspow-spec, scheme v1).
"""
from __future__ import annotations

import hashlib
import os
import struct

P_STRING = b"Tor hs intro v1\x00"  # Tor v1 personalization; protocol bytes must never be translated
UINT32_MAX = 2 ** 32 - 1
UINT128_MAX = 2 ** 128 - 1


def _fixed_bytes(value: bytes, length: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{label} must be exactly {length} bytes")


def _effort(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MAX:
        raise ValueError("must be an unsigned 32-bit integer")


def check_value(service_id: bytes, seed: bytes, nonce: bytes, effort: int,
                solution: bytes) -> int:
    """Compute R = big-endian BLAKE2b-32(P | ID | C | N | E | S)."""
    _fixed_bytes(service_id, 32, "blinded service identity")
    _fixed_bytes(seed, 32, "PoW seed")
    _fixed_bytes(nonce, 16, "PoW nonce")
    _fixed_bytes(solution, 16, "Equi-X proof bytes")
    _effort(effort)
    challenge = P_STRING + service_id + seed + nonce + struct.pack(">I", effort)
    # BLAKE2b-32 uses digest_size=4, not the first 4 bytes of BLAKE2b-512.
    return int.from_bytes(hashlib.blake2b(challenge + solution, digest_size=4).digest(), "big")


def valid_effort(r: int, effort: int) -> bool:
    """Check R × E <= 2^32 - 1; this alone NEVER validates an Equi-X proof."""
    if isinstance(r, bool) or not isinstance(r, int) or not 0 <= r <= UINT32_MAX:
        raise ValueError("R must be an unsigned 32-bit integer")
    _effort(effort)
    return r * effort <= UINT32_MAX


def _increment_nonce(nonce: bytes) -> bytes:
    """Increment a 16-byte little-endian nonce modulo 2^128."""
    _fixed_bytes(nonce, 16, "PoW nonce")
    return ((int.from_bytes(nonce, "little") + 1) & UINT128_MAX).to_bytes(16, "little")


def required_attempts(effort: int, service_id: bytes, seed: bytes,
                       max_attempts: int = 10000) -> int:
    """Count at most max_attempts simulated candidates; not a real Equi-X solver."""
    _effort(effort)
    _fixed_bytes(service_id, 32, "blinded service identity")
    _fixed_bytes(seed, 32, "PoW seed")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")
    nonce = os.urandom(16)
    for attempts in range(1, max_attempts + 1):
        candidate = os.urandom(16)  # Statistical surrogate, NEVER an Equi-X solution.
        if valid_effort(check_value(service_id, seed, nonce, effort, candidate), effort):
            return attempts
        nonce = _increment_nonce(nonce)
    raise RuntimeError("simulated proof not found within max_attempts")
