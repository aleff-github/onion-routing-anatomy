# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
from pathlib import Path

import pytest

from torlab.celle import Cella, Comando, ErroreCella, cella_versions, codifica
from torlab.traffico import celle_da_follow


def test_sequenza_reale():
    testo = (Path(__file__).parent / "dati" / "follow-tls.txt").read_text()
    seq = [(v, Comando(c.comando).name) for v, c, _ in celle_da_follow(testo)]
    assert seq == [("client", "VERSIONS"), ("relay", "VERSIONS"), ("relay", "CERTS"),
                   ("relay", "AUTH_CHALLENGE"), ("relay", "NETINFO"), ("client", "NETINFO"),
                   ("client", "CREATE2"), ("relay", "CREATED2")]


def _follow_sintetico(client_versions: list[int], relay_versions: list[int], 
                     versione_attesa: int) -> str:
    """Due versioni offerte e un NETINFO del relay nello stesso blocco TLS."""
    a = codifica(cella_versions(client_versions), 0)
    b = (codifica(cella_versions(relay_versions), 0) +
         codifica(Cella(0, Comando.NETINFO, b"test"), versione_attesa))
    return "Follow: tls,raw\nNode 0: relay\nNode 1: client\n\t" + a.hex() + "\n" + b.hex() + "\n"


def test_versione_4_negoziata_invece_di_assumere_5():
    traccia = _follow_sintetico([4, 5], [3, 4], 4)
    risultato = celle_da_follow(traccia)
    assert [(v, c.comando, ver) for v, c, ver in risultato] == [
        ("client", Comando.VERSIONS, 0),
        ("relay", Comando.VERSIONS, 0),
        ("relay", Comando.NETINFO, 4),
    ]


def test_versione_3_usa_circid_di_2_byte():
    risultato = celle_da_follow(_follow_sintetico([3], [3], 3))
    assert risultato[-1][2] == 3
    assert risultato[-1][1].comando == Comando.NETINFO


def test_senza_versione_comune_e_errore():
    with pytest.raises(ErroreCella, match="nessuna versione"):
        celle_da_follow(_follow_sintetico([5], [4], 4))


def test_cattura_senza_verso_relay_non_e_considerata_verificata():
    messaggio = codifica(cella_versions([4, 5]), 0).hex()
    with pytest.raises(ErroreCella, match="cattura incompleta"):
        celle_da_follow("Follow: tls,raw\nNode 0: client\n" + messaggio + "\n")
