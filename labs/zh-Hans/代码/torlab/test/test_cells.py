# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import pytest

from torlab.cells import (CELL_BODY_LEN, Cell, CellCommand, RelayCommand, CellError,
                          RelayMessage, destroy_cell, versions_cell, encode,
                          encode_relay, decode, decode_relay, negotiate_version)


def test_fixed_cell_lengths():
    # CELL_LEN(v) = 1 + CIRCID_LEN(v) + 509
    assert len(encode(Cell(0, CellCommand.PADDING), 3)) == 512
    assert len(encode(Cell(0, CellCommand.PADDING), 4)) == 514


def test_circid_command_classes():
    # 通道级命令使用零 CircID；电路级命令使用非零 CircID。
    with pytest.raises(CellError):
        encode(Cell(1, CellCommand.PADDING), 4)
    with pytest.raises(CellError):
        encode(Cell(0, CellCommand.CREATE2), 4)
    assert encode(Cell(0, CellCommand.NETINFO), 4)
    assert encode(Cell(1, CellCommand.CREATE2), 4)


def test_versions_always_uses_two_byte_circid():
    raw = encode(versions_cell([3, 4, 5]), version=5)
    assert raw == bytes.fromhex("0000 07 0006 0003 0004 0005")


def test_encode_decode_roundtrip_with_fragmented_stream():
    version = 5
    cell_stream = (encode(Cell(0x80000001, CellCommand.CREATE2, b"abc"), version)
              + encode(Cell(0, CellCommand.VPADDING, b"xyz"), version))
    # 首个输入分片尚不完整。
    assert decode(cell_stream[:100], version) is None
    c1, remaining = decode(cell_stream, version)
    assert c1.circ_id == 0x80000001 and c1.command == CellCommand.CREATE2
    assert c1.body == b"abc" + b"\x00" * (CELL_BODY_LEN - 3)
    c2, remaining = decode(remaining, version)
    assert (c2.command, c2.body, remaining) == (CellCommand.VPADDING, b"xyz", b"")


def test_negotiation():
    assert negotiate_version([3, 4, 5], bytes.fromhex("000300040005")) == 5
    assert negotiate_version([4, 5], bytes.fromhex("00030004")) == 4
    with pytest.raises(CellError):
        negotiate_version([4, 5], bytes.fromhex("0003"))
    with pytest.raises(CellError):
        negotiate_version([4, 5], bytes.fromhex("000400"))


def test_destroy():
    assert destroy_cell(7).body == b"\x00"
    with pytest.raises(CellError):
        destroy_cell(0)


def test_relay_message():
    msg = RelayMessage(RelayCommand.BEGIN, 1, b"example.com:80\x00")
    body = encode_relay(msg, random_bytes=lambda n: b"\xAA" * n)
    assert len(body) == CELL_BODY_LEN
    assert body[:11].hex() == "01" "0000" "0001" "00000000" "000f"
    assert body[11 + 15:11 + 19] == b"\x00" * 4       # 四个零填充字节
    assert body[-1] == 0xAA                          # 后续填充为随机字节
    assert decode_relay(body) == msg


def test_relay_data_too_long():
    with pytest.raises(CellError):
        encode_relay(RelayMessage(RelayCommand.DATA, 1, b"x" * 499))
