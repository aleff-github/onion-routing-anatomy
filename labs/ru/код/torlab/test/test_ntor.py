# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Тесты лабораторной работы 3 с официальными тестовыми векторами из предложений 216 и 332."""
import pytest

from torlab.ntor import (HandshakeError, create2_body, extend2_body,
                         encode_extensions, complete_create_fast, decode_extensions,
                         kdf_rfc5869, kdf_tor, NTOR_M_EXPAND, NTOR_T_KEY, ntor3_client_finish,
                         ntor3_client_start)

h = bytes.fromhex


def test_hkdf_vectors_proposal_216():
    # Предложение 216 задаёт HKDF с salt = T_KEY и info = M_EXPAND; извлечение
    # HMAC(T_KEY, input) формирует KEY_SEED для этапа расширения.
    import hashlib, hmac
    for input_data, expected in [
        (b"", "d3490ed48b12a48f9547861583573fe3f19aafe3f81dc7fc75eeed96d741b3290f941576c1f9f0b2"
              "d463d1ec7ab2c6bf71cdd7f826c6298c00dbfe6711635d7005f0269493edf6046cc7e7dcf6abe0d2"
              "0c77cf363e8ffe358927817a3d3e73712cee28d8"),
        (b"Tor", "5521492a85139a8d9107a2d5c0d9c91610d0f95989975ebee6c02a4f8d622a6cfdf9b7c7edd3832e"
                 "2760ded1eac309b76f8d66c4a3c4d6225429b3a016e3c3d45911152fc87bc2de9630c3961be9fdb9"
                 "f93197ea8e5977180801926d3321fa21513e59ac"),
    ]:
        key_seed = hmac.new(NTOR_T_KEY, input_data, hashlib.sha256).digest()
        assert kdf_rfc5869(key_seed, NTOR_M_EXPAND, 100).hex() == expected


# Тестовые векторы предложения 332, раздел X.2.
V = dict(
    b="4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a",
    B="f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d",
    ID="9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2",
    x="b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49",
    CM="68656c6c6f20776f726c64", VER="78797a7a79", SM="486f6c61204d756e646f",
    client="9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74"
           "dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995"
           "184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd4"
           "61942088502f67",
    server="4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f"
           "57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c",
    keystream_start="9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3b",
)


def test_ntor3_vectors_proposal_332():
    st, hdata = ntor3_client_start(h(V["ID"]), h(V["B"]), h(V["CM"]), ver=h(V["VER"]), x=h(V["x"]))
    assert hdata.hex() == V["client"]
    sm, key_stream = ntor3_client_finish(st, h(V["server"]), length=256)
    assert sm == h(V["SM"])
    assert key_stream[:32].hex() == V["keystream_start"]


def test_ntor3_modified_auth():
    st, _ = ntor3_client_start(h(V["ID"]), h(V["B"]), h(V["CM"]), ver=h(V["VER"]), x=h(V["x"]))
    response = bytearray(h(V["server"]))
    response[40] ^= 1
    with pytest.raises(HandshakeError):
        ntor3_client_finish(st, bytes(response))


def test_ntor3_different_ver():
    st, _ = ntor3_client_start(h(V["ID"]), h(V["B"]), h(V["CM"]), ver="другая версия".encode("utf-8"), x=h(V["x"]))
    with pytest.raises(HandshakeError):
        ntor3_client_finish(st, h(V["server"]))


def test_kdf_tor():
    assert len(kdf_tor(b"k", 92)) == 92
    with pytest.raises(ValueError):
        kdf_tor(b"k", 5121)


def test_create_fast():
    import os
    x, y = os.urandom(20), os.urandom(20)
    k = kdf_tor(x + y, 92)
    keys = complete_create_fast(x, y + k[:20])
    assert keys.Df == k[20:40] and keys.Kb == k[76:92]
    with pytest.raises(HandshakeError):
        complete_create_fast(x, y + bytes(20))


def test_formats():
    assert create2_body(3, b"ab") == h("0003" "0002") + b"ab"
    assert decode_extensions(encode_extensions([(1, b""), (3, b"\x02\x06")])) == [(1, b""), (3, b"\x02\x06")]
    e = extend2_body("127.0.0.1", 5104, bytes(20), bytes(32), 3, b"")
    assert e[:9].hex() == "03" "00" "06" "7f000001" "13f0"
    assert len(e) == 1 + (2 + 6) + (2 + 20) + (2 + 32) + 4


from torlab import ntor as _ntor_checked


def test_sequence140_reject_truncated_handshakes():
    """Отклонять усечённые ответы CREATE_FAST, ntor и ntor-v3."""
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.complete_create_fast(bytes(20), bytes(39))
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.complete_create_fast(bytes(19), bytes(40))
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.ntor_client_start(bytes(19), bytes(32))
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.ntor_client_start(bytes(20), bytes(31))
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.ntor3_client_start(bytes(31), bytes(32), b"")
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.ntor3_client_start(bytes(32), bytes(31), b"")
    state, _ = _ntor_checked.ntor3_client_start(bytes(32), h(V["B"]), b"")
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.ntor3_client_finish(state, bytes(63))


def test_sequence140_reject_bad_key_lengths_and_kdfs():
    """Отклонять неправильные размеры ключей и длины KDF."""
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.CircuitKeys.from_stream(bytes(71))
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.aes_ctr(bytes(24), b"payload")
    for length in (-1, 5121):
        with pytest.raises(ValueError):
            _ntor_checked.kdf_tor(b"seed", length)
    for length in (-1, 8161):
        with pytest.raises(ValueError):
            _ntor_checked.kdf_rfc5869(bytes(32), b"info", length)
    with pytest.raises(ValueError):
        _ntor_checked._kdf3(b"seed", b"tweak", -1)


def test_sequence140_reject_bad_extensions():
    """Отклонять неверные заголовки расширений, недопустимое их количество и лишние байты."""
    assert _ntor_checked.decode_extensions(b"\x00") == []
    for malformed in (b"", b"\x01", b"\x01\x01", b"\x01\x01\x02\xff", b"\x00\x00"):
        with pytest.raises(_ntor_checked.HandshakeError):
            _ntor_checked.decode_extensions(malformed)
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.encode_extensions([(1, b"")] * 256)
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.encode_extensions([(256, b"")])
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.encode_extensions([(1, bytes(256))])


def test_sequence140_reject_bad_cell_fields():
    """Отклонять неверное кодирование CREATE2 и EXTEND2."""
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.hdata_created2(b"\x00")
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.hdata_created2(b"\x00\x03ab")
    assert _ntor_checked.hdata_created2(b"\x00\x02ab\x00") == b"ab"
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.create2_body(-1, b"")
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.create2_body(3, bytes(65536))
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.extend2_body("999.0.0.1", 5104, bytes(20), bytes(32), 3, b"")
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.extend2_body("127.0.0.1", 0, bytes(20), bytes(32), 3, b"")
    with pytest.raises(_ntor_checked.HandshakeError):
        _ntor_checked.extend2_body("127.0.0.1", 5104, bytes(19), bytes(32), 3, b"")
