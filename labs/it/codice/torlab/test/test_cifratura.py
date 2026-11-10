# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Test del Laboratorio 4: un circuito simulato di tre relay in memoria."""
import os

import pytest

from torlab.celle import MessaggioRelay
from torlab.cifratura import CircuitoClient, Direzione, ErroreCella, Salto, SaltoRelay
from torlab.ntor import ChiaviCircuito


def circuito(n=3):
    chiavi = [ChiaviCircuito.da_flusso(os.urandom(72)) for _ in range(n)]
    client = CircuitoClient([Salto.da_chiavi(k) for k in chiavi])
    relay = [SaltoRelay(Salto.da_chiavi(k)) for k in chiavi]
    return client, relay


def attraversa(relay, corpo):
    """Fa passare una cella in avanti; restituisce (indice di chi la riconosce, corpo)."""
    for i, r in enumerate(relay):
        riconosciuta, corpo = r.dal_client(corpo)
        if riconosciuta:
            return i, corpo
    return None, corpo


def test_ogni_salto_riceve_solo_le_proprie_celle():
    client, relay = circuito()
    for dest in (2, 0, 1, 2, 2, 0):
        msg = MessaggioRelay(2, 7, f"per il salto {dest}".encode())
        i, corpo = attraversa(relay, client.cifra(msg, dest))
        assert i == dest
        assert corpo[11:11 + len(msg.dati)] == msg.dati


def test_i_relay_intermedi_vedono_solo_rumore():
    client, relay = circuito()
    msg = MessaggioRelay(2, 7, b"segreto" * 10)
    corpo = client.cifra(msg, 2)
    _, dopo_primo = relay[0].dal_client(corpo)
    assert b"segreto" not in dopo_primo


def test_direzione_indietro():
    client, relay = circuito()
    for origine in (2, 1, 2, 0):
        msg = MessaggioRelay(4, 7, f"dal salto {origine}".encode())
        corpo = relay[origine].verso_client(msg)
        for j in range(origine - 1, -1, -1):          # i relay precedenti aggiungono uno strato
            corpo = relay[j].inoltra_verso_client(corpo)
        i, ricevuto = client.decifra(corpo)
        assert i == origine and ricevuto.dati == msg.dati


def test_modifica_rilevata_a_destinazione():
    client, relay = circuito()
    corpo = bytearray(client.cifra(MessaggioRelay(2, 7, b"ciao"), 2))
    corpo[100] ^= 0x01                                 # un bit alterato in transito
    i, _ = attraversa(relay, bytes(corpo))
    assert i is None                                   # l'exit non la riconosce


def test_tagging_malleabilita_ctr():
    """AES-CTR è malleabile: chi conosce il testo in chiaro può cambiarlo
    senza conoscere le chiavi; solo il digest all'estremo lo rivela."""
    client, relay = circuito(1)
    msg = MessaggioRelay(2, 7, b"paga 10 euro")
    corpo = bytearray(client.cifra(msg, 0))
    pos = 11 + msg.dati.index(b"10")
    for k, (vecchio, nuovo) in enumerate(zip(b"10", b"99")):
        corpo[pos + k] ^= vecchio ^ nuovo
    riconosciuta, chiaro = relay[0].dal_client(bytes(corpo))
    assert b"paga 99 euro" in chiaro                  # il testo è cambiato...
    assert not riconosciuta                           # ...ma il digest se ne accorge


def test_cella_indietro_corrotta():
    client, relay = circuito()
    corpo = bytearray(relay[2].verso_client(MessaggioRelay(4, 7, b"x")))
    corpo[50] ^= 0xFF
    corpo = relay[0].inoltra_verso_client(relay[1].inoltra_verso_client(bytes(corpo)))
    with pytest.raises(ErroreCella):
        client.decifra(corpo)

def test_invalid_tor1_cell_lengths():
    # Le eccezioni per lunghezza errata non devono avanzare né il cifrario né il digest.
    client, relay = circuito(1)
    with pytest.raises(ErroreCella):
        client.decifra(bytes(508))
    with pytest.raises(ErroreCella):
        client.decifra(bytes(510))
    with pytest.raises(ErroreCella):
        relay[0].dal_client(bytes(508))
    # I rifiuti sono avvenuti prima dell'aggiornamento AES; una cella valida funziona ancora.
    msg = MessaggioRelay(2, 7, b"normale")
    outbound = client.cifra(msg, 0)
    recognized, _ = relay[0].dal_client(outbound)
    assert recognized


def test_invalid_direction_keys_and_hop_indices():
    with pytest.raises(ErroreCella):
        Direzione.nuova(bytes(15), bytes(20))
    with pytest.raises(ErroreCella):
        Direzione.nuova(bytes(16), bytes(19))
    client, relay = circuito(1)
    for hop in (-1, 1, 100):
        with pytest.raises(ErroreCella):
            client.cifra(MessaggioRelay(2, 7, b"test"), hop)
    msg = MessaggioRelay(2, 7, b"inalterato")
    recognized, _ = relay[0].dal_client(client.cifra(msg, 0))
    assert recognized


def test_unrecognized_cell_does_not_advance_rolling_digest():
    direction = Direzione.nuova(bytes(16), bytes(20))
    baseline = direction.digest.copy().digest()
    assert not direction.riconosce(bytes(509))
    assert direction.digest.digest() == baseline
    with pytest.raises(ErroreCella):
        direction.riconosce(bytes(10))
    assert direction.digest.digest() == baseline
