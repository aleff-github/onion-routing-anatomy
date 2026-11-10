# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import statistics

from torlab.pow import UINT32_MAX, valid_effort, required_attempts


def test_threshold():
    assert valid_effort(UINT32_MAX // 100, 100)
    assert not valid_effort(UINT32_MAX // 100 + 1, 100)
    assert valid_effort(UINT32_MAX, 1)        # esfuerzo 1: todo R válido supera el umbral (no valida Equi-X)


def test_linear_effort():
    means = {e: statistics.mean(required_attempts(e, bytes(32), bytes(32)) for _ in range(300))
             for e in (10, 40)}
    assert 0.7 * 10 < means[10] < 1.3 * 10
    assert 0.7 * 40 < means[40] < 1.3 * 40


import hashlib
import struct

import pytest
from torlab import pow as _pow143


def test_sequence143_digest_is_blake2b32():
    """Se usa BLAKE2b-32, no un prefijo de BLAKE2b-512."""
    identity = bytes(range(32))
    seed = bytes(reversed(range(32)))
    nonce = bytes(range(16))
    proof = bytes(reversed(range(16)))
    effort = 42
    data = _pow143.P_STRING + identity + seed + nonce + struct.pack(">I", effort) + proof
    expected = int.from_bytes(hashlib.blake2b(data, digest_size=4).digest(), "big")
    assert _pow143.check_value(identity, seed, nonce, effort, proof) == expected
    assert hashlib.blake2b(data, digest_size=4).digest() != hashlib.blake2b(data).digest()[:4]


def test_sequence143_reject_invalid_fields_and_effort():
    """Se comprueban los tamaños de los campos y los límites del esfuerzo."""
    inputs = (bytes(32), bytes(32), bytes(16), 3, bytes(16))
    for i, bad in ((0, bytes(31)), (1, bytes(31)), (2, bytes(15)),
                   (3, -1), (3, _pow143.UINT32_MAX + 1),
                   (3, True), (4, bytes(15))):
        values = list(inputs)
        values[i] = bad
        with pytest.raises(ValueError):
            _pow143.check_value(*values)
    for r, effort in ((-1, 1), (_pow143.UINT32_MAX + 1, 1), (1, -1),
                      (1, _pow143.UINT32_MAX + 1), (True, 2), (2, True)):
        with pytest.raises(ValueError):
            _pow143.valid_effort(r, effort)
    assert _pow143.valid_effort(_pow143.UINT32_MAX, 0)
    assert _pow143.valid_effort(_pow143.UINT32_MAX, 1)
    assert not _pow143.valid_effort(_pow143.UINT32_MAX, 2)


def test_sequence143_nonce_wraparound():
    """El nonce little-endian de 16 bytes se desborda correctamente."""
    assert _pow143._increment_nonce(bytes(16)) == b"\x01" + bytes(15)
    assert _pow143._increment_nonce(b"\xff" * 16) == bytes(16)
    with pytest.raises(ValueError):
        _pow143._increment_nonce(bytes(15))


def test_sequence143_bounded_simulation(monkeypatch):
    """La simulación tiene un límite de intentos y no produce pruebas Equi-X."""
    identity, seed = bytes(32), bytes(32)
    with pytest.raises(ValueError):
        _pow143.required_attempts(3, identity, seed, max_attempts=0)
    with pytest.raises(ValueError):
        _pow143.required_attempts(3, identity, seed, max_attempts=True)
    with pytest.raises(ValueError):
        _pow143.required_attempts(3, identity, bytes(31))
    monkeypatch.setattr(_pow143, "check_value", lambda *args: _pow143.UINT32_MAX)
    with pytest.raises(RuntimeError):
        _pow143.required_attempts(2, identity, seed, max_attempts=3)
