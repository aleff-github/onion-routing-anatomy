# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Тесты лабораторной работы 4: имитация цепи из трёх ретрансляторов в памяти."""
import os

import pytest

from torlab.cells import RelayMessage
from torlab.encryption import ClientCircuitCrypto, Direction, CellError, Hop, RelayHop
from torlab.ntor import CircuitKeys


def circuit(n=3):
    keys = [CircuitKeys.from_stream(os.urandom(72)) for _ in range(n)]
    client = ClientCircuitCrypto([Hop.from_keys(k) for k in keys])
    relay = [RelayHop(Hop.from_keys(k)) for k in keys]
    return client, relay


def traverse(relay, body):
    """Передать ячейку вперёд; вернуть (индекс распознавшего её ретранслятора, тело ячейки)."""
    for i, r in enumerate(relay):
        recognized, body = r.from_client(body)
        if recognized:
            return i, body
    return None, body


def test_each_hop_receives_only_its_cells():
    client, relay = circuit()
    for dest in (2, 0, 1, 2, 2, 0):
        msg = RelayMessage(2, 7, f"для узла {dest}".encode())
        i, body = traverse(relay, client.encrypt(msg, dest))
        assert i == dest
        assert body[11:11 + len(msg.data)] == msg.data


def test_middle_relays_see_only_noise():
    client, relay = circuit()
    msg = RelayMessage(2, 7, "секрет".encode() * 10)
    body = client.encrypt(msg, 2)
    _, after_first = relay[0].from_client(body)
    assert "секрет".encode() not in after_first


def test_backward_direction():
    client, relay = circuit()
    for origin in (2, 1, 2, 0):
        msg = RelayMessage(4, 7, f"от узла {origin}".encode())
        body = relay[origin].to_client(msg)
        for j in range(origin - 1, -1, -1):          # предыдущие ретрансляторы добавляют по одному слою
            body = relay[j].forward_to_client(body)
        i, received = client.decrypt(body)
        assert i == origin and received.data == msg.data


def test_modification_detected_at_destination():
    client, relay = circuit()
    body = bytearray(client.encrypt(RelayMessage(2, 7, "привет".encode()), 2))
    body[100] ^= 0x01                                 # один бит изменён при передаче
    i, _ = traverse(relay, bytes(body))
    assert i is None                                  # выходной ретранслятор не распознаёт ячейку


def test_ctr_tagging_malleability():
    """AES-CTR допускает предсказуемую модификацию: зная открытый текст, можно изменить шифртекст
    без знания ключей; изменение обнаруживается дайджестом в конечной точке."""
    client, relay = circuit(1)
    msg = RelayMessage(2, 7, "заплати 10 евро".encode())
    body = bytearray(client.encrypt(msg, 0))
    pos = 11 + msg.data.index(b"10")
    for k, (old, new) in enumerate(zip(b"10", b"99")):
        body[pos + k] ^= old ^ new
    recognized, plaintext = relay[0].from_client(bytes(body))
    assert "заплати 99 евро".encode() in plaintext                  # открытый текст изменился...
    assert not recognized                                # ...но дайджест обнаруживает подмену


def test_corrupted_backward_cell():
    client, relay = circuit()
    body = bytearray(relay[2].to_client(RelayMessage(4, 7, b"x")))
    body[50] ^= 0xFF
    body = relay[0].forward_to_client(relay[1].forward_to_client(bytes(body)))
    with pytest.raises(CellError):
        client.decrypt(body)

def test_invalid_tor1_cell_lengths():
    # Неверная длина не должна изменять счётчик AES-CTR или текущий дайджест.
    client, relay = circuit(1)
    with pytest.raises(CellError):
        client.decrypt(bytes(508))
    with pytest.raises(CellError):
        client.decrypt(bytes(510))
    with pytest.raises(CellError):
        relay[0].from_client(bytes(508))
    # Отказы не меняли состояние AES; корректная ячейка по-прежнему проходит.
    msg = RelayMessage(2, 7, "обычная".encode())
    outbound = client.encrypt(msg, 0)
    recognized, _ = relay[0].from_client(outbound)
    assert recognized


def test_invalid_direction_keys_and_hop_indices():
    with pytest.raises(CellError):
        Direction.new(bytes(15), bytes(20))
    with pytest.raises(CellError):
        Direction.new(bytes(16), bytes(19))
    client, relay = circuit(1)
    for hop in (-1, 1, 100):
        with pytest.raises(CellError):
            client.encrypt(RelayMessage(2, 7, b"test"), hop)
    msg = RelayMessage(2, 7, "без изменений".encode())
    recognized, _ = relay[0].from_client(client.encrypt(msg, 0))
    assert recognized


def test_unrecognized_cell_does_not_advance_rolling_digest():
    direction = Direction.new(bytes(16), bytes(20))
    baseline = direction.digest.copy().digest()
    assert not direction.recognizes(bytes(509))
    assert direction.digest.digest() == baseline
    with pytest.raises(CellError):
        direction.recognizes(bytes(10))
    assert direction.digest.digest() == baseline
