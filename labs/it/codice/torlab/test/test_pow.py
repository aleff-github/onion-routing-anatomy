# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import statistics

from torlab.pow import UINT32_MAX, sforzo_valido, tentativi_necessari


def test_soglia():
    assert sforzo_valido(UINT32_MAX // 100, 100)
    assert not sforzo_valido(UINT32_MAX // 100 + 1, 100)
    assert sforzo_valido(UINT32_MAX, 1)        # sforzo 1: ogni R valido supera la soglia (non convalida Equi-X)


def test_sforzo_lineare():
    medie = {e: statistics.mean(tentativi_necessari(e, bytes(32), bytes(32)) for _ in range(300))
             for e in (10, 40)}
    assert 0.7 * 10 < medie[10] < 1.3 * 10
    assert 0.7 * 40 < medie[40] < 1.3 * 40


import hashlib
import struct

import pytest
from torlab import pow as _pow143


def test_sequence143_digest_is_blake2b32():
    """Si usa BLAKE2b-32 e non un prefisso del digest BLAKE2b-512."""
    identity = bytes(range(32))
    seed = bytes(reversed(range(32)))
    nonce = bytes(range(16))
    proof = bytes(reversed(range(16)))
    effort = 42
    data = _pow143.P_STRING + identity + seed + nonce + struct.pack(">I", effort) + proof
    expected = int.from_bytes(hashlib.blake2b(data, digest_size=4).digest(), "big")
    assert _pow143.valore_controllo(identity, seed, nonce, effort, proof) == expected
    assert hashlib.blake2b(data, digest_size=4).digest() != hashlib.blake2b(data).digest()[:4]


def test_sequence143_reject_invalid_fields_and_effort():
    """Si verificano le dimensioni dei campi e i limiti dello sforzo."""
    inputs = (bytes(32), bytes(32), bytes(16), 3, bytes(16))
    for i, bad in ((0, bytes(31)), (1, bytes(31)), (2, bytes(15)),
                   (3, -1), (3, _pow143.UINT32_MAX + 1),
                   (3, True), (4, bytes(15))):
        values = list(inputs)
        values[i] = bad
        with pytest.raises(ValueError):
            _pow143.valore_controllo(*values)
    for r, effort in ((-1, 1), (_pow143.UINT32_MAX + 1, 1), (1, -1),
                      (1, _pow143.UINT32_MAX + 1), (True, 2), (2, True)):
        with pytest.raises(ValueError):
            _pow143.sforzo_valido(r, effort)
    assert _pow143.sforzo_valido(_pow143.UINT32_MAX, 0)
    assert _pow143.sforzo_valido(_pow143.UINT32_MAX, 1)
    assert not _pow143.sforzo_valido(_pow143.UINT32_MAX, 2)


def test_sequence143_nonce_wraparound():
    """Il nonce little-endian di 16 byte riparte correttamente da zero."""
    assert _pow143._increment_nonce(bytes(16)) == b"\x01" + bytes(15)
    assert _pow143._increment_nonce(b"\xff" * 16) == bytes(16)
    with pytest.raises(ValueError):
        _pow143._increment_nonce(bytes(15))


def test_sequence143_bounded_simulation(monkeypatch):
    """La simulazione ha un limite di tentativi e non produce prove Equi-X."""
    identity, seed = bytes(32), bytes(32)
    with pytest.raises(ValueError):
        _pow143.tentativi_necessari(3, identity, seed, max_attempts=0)
    with pytest.raises(ValueError):
        _pow143.tentativi_necessari(3, identity, seed, max_attempts=True)
    with pytest.raises(ValueError):
        _pow143.tentativi_necessari(3, identity, bytes(31))
    monkeypatch.setattr(_pow143, "valore_controllo", lambda *args: _pow143.UINT32_MAX)
    with pytest.raises(RuntimeError):
        _pow143.tentativi_necessari(2, identity, seed, max_attempts=3)
