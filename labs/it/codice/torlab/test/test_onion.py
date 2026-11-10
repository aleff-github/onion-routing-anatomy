# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Test del Laboratorio 8 su un descrittore reale della rete di laboratorio (in dati/)."""
from pathlib import Path

import pytest

from torlab.onion import (analizza_descrittore, chiave_accecata, chiave_da_indirizzo,
                          indirizzo_onion, tempo)

DATI = Path(__file__).parent / "dati"
INDIRIZZO = (DATI / "descrittore-onion.indirizzo").read_text().strip()
TESTO = (DATI / "descrittore-onion.txt").read_text()
PERIODO, DURATA = 3729540, 8          # periodo in cui il descrittore è stato scaricato


def test_indirizzi_della_specifica():
    for a in ("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
              "sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion",
              "xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion"):
        assert indirizzo_onion(chiave_da_indirizzo(a)) == a


def test_checksum_sbagliato():
    sbagliato = INDIRIZZO[:10] + ("a" if INDIRIZZO[10] != "a" else "b") + INDIRIZZO[11:]
    with pytest.raises(ValueError):
        chiave_da_indirizzo(sbagliato)


def test_descrittore_reale():
    A = chiave_da_indirizzo(INDIRIZZO)
    d = analizza_descrittore(TESTO, A, chiave_accecata(A, PERIODO, DURATA))
    assert d.durata_minuti == 180 and len(d.punti_di_introduzione) == 3


def test_periodo_sbagliato_rifiutato():
    A = chiave_da_indirizzo(INDIRIZZO)
    with pytest.raises(ValueError):
        analizza_descrittore(TESTO, A, chiave_accecata(A, PERIODO + 1, DURATA))


def test_tempo_rete_pubblica():
    # Esempio della specifica: 2016-04-13 11:15:01 UTC → periodo 16903 (voto di un'ora).
    assert tempo(1460546101, 3600, rete_di_test=False).periodo == 16903



def test_srv_di_emergenza_serializzazione_int8():
    """Vettore indipendente derivato da rend-spec (non pubblicato dal Tor Project).

    La durata precede il numero del periodo; entrambi sono u64 big-endian.
    Evita regressioni se cambiano ordine, dimensione o codifica dei campi.
    """
    from torlab.onion import Tempo, srv_disastro

    assert srv_disastro(Tempo(16903, 1440, False)).hex() == (
        "e7a6d7d2d9de116d1d8b5d49cdf3d070555a0fa60950ca6844ebcb88828b9f53"
    )
    assert srv_disastro(Tempo(3729540, 8, True)).hex() == (
        "5a4c2f52c260b1481ad03aa4e0c90717bbaa7c35f9f42295fa2456fcbcd1fdb0"
    )


def test_indici_hsdir_serializzazione_int8():
    """Vettori derivati da rend-spec: ogni intero occupa 8 byte big-endian.

    La fixture fissa rileva regressioni nell'ordine dei campi, nella lunghezza
    della replica e nell'endianess; non è un vettore pubblicato dal Tor Project.
    """
    from torlab.onion import Tempo, indice_relay, indice_servizio

    t = Tempo(16903, 1440, False)
    identificativo = bytes(range(32, 64))
    casualita = bytes(range(64, 96))
    accecata = bytes(range(32))

    assert indice_relay(identificativo, casualita, t).hex() == (
        "b9305152355cdf78316ca83e3cf5a3bb17880215b5d688eaa03c1667fc38ed61"
    )
    assert indice_servizio(accecata, 2, t).hex() == (
        "6c4a9aba051974769503bc53e4624a753aa2059f2fda7076c6649ec5139aded4"
    )



from torlab import onion as _onion_checked


def test_sequence141_reject_invalid_onion_addresses():
    """Gli indirizzi onion non validi e i punti non canonici sono rifiutati."""
    with pytest.raises(ValueError):
        _onion_checked.indirizzo_onion(bytes(31))
    for invalid in ("example.onion", "a" * 56 + ".onion",
                    INDIRIZZO.removesuffix(".onion"),
                    "0" + INDIRIZZO[1:]):
        with pytest.raises(ValueError):
            _onion_checked.chiave_da_indirizzo(invalid)
    with pytest.raises(ValueError):
        _onion_checked._decodifica(bytes(31))
    with pytest.raises(ValueError):
        _onion_checked._decodifica(_onion_checked.P.to_bytes(32, "little"))
    with pytest.raises(ValueError):
        _onion_checked._decodifica((1 | (1 << 255)).to_bytes(32, "little"))


def test_sequence141_validate_time_and_hsdir_ring():
    """Sono validati periodi e parametri dell'anello HSDir."""
    with pytest.raises(ValueError):
        _onion_checked.tempo(1460546101, 0, False)
    with pytest.raises(ValueError):
        _onion_checked.tempo(-1, 3600, False)
    t = _onion_checked.tempo(1460546101, 3600, False)
    with pytest.raises(ValueError):
        _onion_checked.hsdir_responsabili(bytes(32), [], bytes(32), t)
    with pytest.raises(ValueError):
        _onion_checked.hsdir_responsabili(bytes(32), [("a", bytes(32))] * 6, bytes(32), t)
    names = [(str(i), bytes([i]) * 32) for i in range(1, 7)]
    groups = _onion_checked.hsdir_responsabili(bytes(32), names, bytes(32), t)
    assert len(groups) == 2
    assert len(set(groups[0] + groups[1])) == 6


def test_sequence141_validate_encrypted_layer_and_pem():
    """Sono verificati MAC e struttura PEM."""
    with pytest.raises(ValueError):
        _onion_checked._decifra_strato(bytes(47), bytes(32), bytes(32), 1, b"hsdir-encrypted-data")
    with pytest.raises(ValueError):
        _onion_checked._decifra_strato(bytes(48), bytes(32), bytes(32), 1, b"hsdir-encrypted-data")
    with pytest.raises(ValueError):
        _onion_checked._oggetto("encrypted\n-----BEGIN MESSAGE-----\n!\n-----END MESSAGE-----", "encrypted")
    with pytest.raises(ValueError):
        _onion_checked._oggetto("encrypted\n-----BEGIN MESSAGE-----\nYQ==", "encrypted")


def test_sequence141_validate_descriptor_fields_and_expiry():
    """Sono controllati metadati e scadenza opzionale del certificato."""
    A = _onion_checked.chiave_da_indirizzo(INDIRIZZO)
    blinded = _onion_checked.chiave_accecata(A, PERIODO, DURATA)
    with pytest.raises(ValueError):
        _onion_checked.analizza_descrittore(TESTO.replace("descriptor-lifetime 180", "descriptor-lifetime 1"), A, blinded)
    with pytest.raises(ValueError):
        _onion_checked.analizza_descrittore(TESTO.replace("revision-counter 662427", "revision-counter 662427\nrevision-counter 662427"), A, blinded)
    with pytest.raises(ValueError, match="certificato di firma del descrittore scaduto"):
        _onion_checked.analizza_descrittore(TESTO, A, blinded,
                         check_expiration=True, reference_time=4102444800)
    with pytest.raises(ValueError):
        _onion_checked.scarica_descrittore(blinded, [])


def test_richiesta_a_un_salto_arriva_all_hsdir(monkeypatch):
    """Regressione (validazione dal vivo, 28/10/2026): il rifiuto a un salto è dell'HSDir
    (503) ed è il controllo negativo del Lab 8; il client non deve impedirlo."""
    from torlab import circuito, directory
    chiamate = []
    monkeypatch.setattr(circuito, "costruisci", lambda percorso, cc: ("circ", len(percorso)))
    monkeypatch.setattr(directory, "scarica", lambda circ, url, sid: chiamate.append((circ, url)) or b"ok")
    assert _onion_checked.scarica_descrittore(bytes(32), ["hsdir"]) == "ok"
    assert chiamate == [(("circ", 1), "/tor/hs/3/" + "A" * 43)]
