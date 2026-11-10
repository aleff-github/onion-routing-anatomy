# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import pytest

from torlab.celle import (CELL_BODY_LEN, Cella, Comando, ComandoRelay, ErroreCella,
                          MessaggioRelay, cella_destroy, cella_versions, codifica,
                          codifica_relay, decodifica, decodifica_relay, negozia_versione)


def test_lunghezza_celle_fisse():
    # CELL_LEN(v) = 1 + CIRCID_LEN(v) + 509
    assert len(codifica(Cella(0, Comando.PADDING), 3)) == 512
    assert len(codifica(Cella(0, Comando.PADDING), 4)) == 514


def test_circid_comandi():
    # I comandi di canale richiedono CircID=0; quelli di circuito, CircID!=0.
    with pytest.raises(ErroreCella):
        codifica(Cella(1, Comando.PADDING), 4)
    with pytest.raises(ErroreCella):
        codifica(Cella(0, Comando.CREATE2), 4)
    assert codifica(Cella(0, Comando.NETINFO), 4)
    assert codifica(Cella(1, Comando.CREATE2), 4)


def test_versions_usa_sempre_circid_di_due_byte():
    grezzo = codifica(cella_versions([3, 4, 5]), versione=5)
    assert grezzo == bytes.fromhex("0000 07 0006 0003 0004 0005")


def test_ciclo_codifica_decodifica_con_flusso_frammentato():
    versione = 5
    flusso = (codifica(Cella(0x80000001, Comando.CREATE2, b"abc"), versione)
              + codifica(Cella(0, Comando.VPADDING, b"xyz"), versione))
    # Il primo frammento è incompleto.
    assert decodifica(flusso[:100], versione) is None
    c1, resto = decodifica(flusso, versione)
    assert c1.circ_id == 0x80000001 and c1.comando == Comando.CREATE2
    assert c1.corpo == b"abc" + b"\x00" * (CELL_BODY_LEN - 3)
    c2, resto = decodifica(resto, versione)
    assert (c2.comando, c2.corpo, resto) == (Comando.VPADDING, b"xyz", b"")


def test_negoziazione():
    assert negozia_versione([3, 4, 5], bytes.fromhex("000300040005")) == 5
    assert negozia_versione([4, 5], bytes.fromhex("00030004")) == 4
    with pytest.raises(ErroreCella):
        negozia_versione([4, 5], bytes.fromhex("0003"))
    with pytest.raises(ErroreCella):
        negozia_versione([4, 5], bytes.fromhex("000400"))


def test_destroy():
    assert cella_destroy(7).corpo == b"\x00"
    with pytest.raises(ErroreCella):
        cella_destroy(0)


def test_messaggio_relay():
    msg = MessaggioRelay(ComandoRelay.BEGIN, 1, b"example.com:80\x00")
    corpo = codifica_relay(msg, casuale=lambda n: b"\xAA" * n)
    assert len(corpo) == CELL_BODY_LEN
    assert corpo[:11].hex() == "01" "0000" "0001" "00000000" "000f"
    assert corpo[11 + 15:11 + 19] == b"\x00" * 4       # 4 zeri di padding
    assert corpo[-1] == 0xAA                          # poi byte casuali
    assert decodifica_relay(corpo) == msg


def test_dati_relay_troppo_lunghi():
    with pytest.raises(ErroreCella):
        codifica_relay(MessaggioRelay(ComandoRelay.DATA, 1, b"x" * 499))
