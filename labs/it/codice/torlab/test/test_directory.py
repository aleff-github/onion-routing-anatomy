# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Test del Laboratorio 6 su un consenso reale della rete di laboratorio (salvato in dati/)."""
from pathlib import Path
import hashlib
from types import SimpleNamespace
import pytest

from torlab.directory import analizza_certificati, analizza_consenso, items, verifica_consenso

DATI = Path(__file__).parent / "dati"
TESTO = (DATI / "consenso-microdesc.txt").read_text()
CERT = analizza_certificati((DATI / "certificati-autorita.txt").read_text())


def test_struttura():
    c = analizza_consenso(TESTO)
    assert c.intestazione["network-status-version"] == ["3", "microdesc"]
    assert len(c.relay) == 8 and len(c.firme) == 3
    assert sum("Exit" in r.flag for r in c.relay) == 2
    assert all(len(r.microdesc) == 32 for r in c.relay)


def test_firme_valide():
    valide, richieste, _ = verifica_consenso(analizza_consenso(TESTO), CERT, 3)
    assert (valide, richieste) == (3, 2)


def test_consenso_alterato():
    alterato = TESTO.replace("Bandwidth=4096", "Bandwidth=4097", 1)
    assert verifica_consenso(analizza_consenso(alterato), CERT, 3)[0] == 0


def test_firma_di_autorita_sconosciuta():
    solo_una = [CERT[0]]
    assert verifica_consenso(analizza_consenso(TESTO), solo_una, 3)[0] == 1


def test_items_con_oggetti():
    it = items("a 1 2\nb\n-----BEGIN X-----\nQUJD\n-----END X-----\nc\n")
    assert [i.parola for i in it] == ["a", "b", "c"]
    assert it[1].oggetto.startswith(b"-----BEGIN X-----")


def test_testo_firmato_ignora_annotazione_collector():
    """I file di CollecTor possono iniziare con "@type ...": non fa parte del testo firmato."""
    from torlab.directory import testo_firmato
    assert testo_firmato("@type network-status-microdesc-consensus-3 1.0\n" + TESTO) == testo_firmato(TESTO)

def test_unterminated_pem_rejected():
    # Il parser non deve superare la fine del documento.
    with pytest.raises(ValueError):
        items("x\n-----BEGIN TEST-----\nQUJD\n")
    with pytest.raises(ValueError):
        items("x\n-----BEGIN TEST-----\nQUJD\n-----END OTHER-----\n")


def test_unknown_signature_algorithm_is_not_sha1():
    from torlab.directory import analizza_consenso, verifica_firma, Firma, testo_firmato
    parsed = analizza_consenso(TESTO)
    digest = hashlib.sha1(testo_firmato(parsed.testo)).digest()
    fake_cert = SimpleNamespace(chiave_firma=SimpleNamespace(
        recover_data_from_signature=lambda *args: digest))
    unknown = Firma("sha999", "00", "11", b"signature")
    assert verifica_firma(parsed, unknown, fake_cert) is False


def test_microdescriptor_collector_annotations_do_not_enter_digest():
    from torlab.directory import analizza_microdescrittori
    first = "onion-key\nntor-onion-key QUJD\n"
    second = "onion-key\nntor-onion-key QUJE\n"
    annotated = first + "@last-listed 2026-09-23 16:00:00\n" + second
    parsed = analizza_microdescrittori(annotated)
    assert hashlib.sha256(first.encode()).digest() in parsed
    assert hashlib.sha256(second.encode()).digest() in parsed
    assert len(parsed) == 2


def test_scarica_su_begin_dir():
    """Regressione: lo stream aperto con BEGIN_DIR deve risultare aperto prima del GET."""
    from torlab.celle import ComandoRelay, MessaggioRelay
    from torlab.directory import scarica

    class CircuitoFinto:
        def __init__(self):
            self.inviati = []
            self.risposte = [MessaggioRelay(ComandoRelay.CONNECTED, 7),
                             MessaggioRelay(ComandoRelay.DATA, 7, b"HTTP/1.0 200 OK\r\n\r\ncorpo"),
                             MessaggioRelay(ComandoRelay.END, 7, bytes([6]))]

        def invia(self, msg):
            self.inviati.append(msg)

        def ricevi(self):
            return 1, self.risposte.pop(0)

        def conta_data_ricevuto(self):
            pass

    circ = CircuitoFinto()
    assert scarica(circ, "/tor/status-vote/current/consensus-microdesc", 7) == b"corpo"
    assert [m.comando for m in circ.inviati] == [ComandoRelay.BEGIN_DIR, ComandoRelay.DATA]
    assert circ.inviati[1].dati.startswith(b"GET /tor/status-vote/current/consensus-microdesc HTTP/1.0")
