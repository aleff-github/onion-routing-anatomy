# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import base64

import pytest

from torlab.canale import ErroreCanale
from torlab.conversione import verifica_crosscert, verifica_identita_descrittore

# Relay test004r della rete di laboratorio (descrittore del 23 settembre 2026).
NTOR = "DaxPE+Grnjex2Hmv+5qutl5dIX4La2jF6MIL7IK6+3E"
CERT = base64.b64decode(
    "AQoAB5kbAZIzyIAwdjhbBic7sLE/ijEvxJfaq5RNv+D+VryL5swvAP3E4+R2wtel"
    "Dy46jK1zCpicy5JBvWZbuavhz2jJfRXh/t5g+lnh0NKGFzxeXZiroUDIHavjV+S0"
    "8f+YbkbdPwk=")
IDENTITA = "kjPIgDB2OFsGJzuwsT+KMS/El9qrlE2/4P5WvIvmzC8"


def test_crosscert_valido(monkeypatch):
    # Il certificato storico era valido il 23 settembre 2026, ma è scaduto il 21 ottobre.
    monkeypatch.setattr("torlab.canale.time.time", lambda: 1790164800)
    chiave = verifica_crosscert(NTOR, 0, CERT)
    assert base64.b64encode(chiave).decode().rstrip("=") == IDENTITA


def test_segno_sbagliato():
    with pytest.raises(ErroreCanale):
        verifica_crosscert(NTOR, 1, CERT)

def test_crosscert_scaduto(monkeypatch):
    # Il certificato storico è scaduto il 21 ottobre 2026 alle 19:00 UTC.
    monkeypatch.setattr("torlab.canale.time.time", lambda: 1792670400)
    with pytest.raises(ValueError, match="scaduto"):
        verifica_crosscert(NTOR, 0, CERT)


def test_crosscert_campi_errati(monkeypatch):
    monkeypatch.setattr("torlab.canale.time.time", lambda: 1790164800)
    with pytest.raises(ValueError):
        verifica_crosscert(NTOR, 2, CERT)
    with pytest.raises(ValueError):
        verifica_crosscert("AQ==", 0, CERT)
    c = bytearray(CERT)
    c[1] = 4  # Il tipo 0x0A è obbligatorio per la cross-certification ntor.
    with pytest.raises(ValueError):
        verifica_crosscert(NTOR, 0, bytes(c))

def test_identita_descrittore_correlata_al_crosscert():
    identita = base64.b64decode(IDENTITA + "=" * (-len(IDENTITA) % 4))
    testo = "test004r 127.0.0.1 5000 0 0\nmaster-key-ed25519 " + IDENTITA + "\n"
    verifica_identita_descrittore(testo, identita)


def test_identita_descrittore_divergente():
    identita = base64.b64decode(IDENTITA + "=" * (-len(IDENTITA) % 4))
    diversa = base64.b64encode(bytes([identita[0] ^ 1]) + identita[1:]).decode().rstrip("=")
    testo = "test004r 127.0.0.1 5000 0 0\nmaster-key-ed25519 " + diversa + "\n"
    with pytest.raises(ValueError, match="non coincide"):
        verifica_identita_descrittore(testo, identita)


@pytest.mark.parametrize("campo", [
    "",
    "master-key-ed25519 " + IDENTITA + "\nmaster-key-ed25519 " + IDENTITA + "\n",
    "master-key-ed25519 " + IDENTITA + "\nmaster-key-ed25519 !!!non-base64!!!\n",
    "master-key-ed25519 " + IDENTITA + "\nmaster-key-ed25519\n",
    "master-key-ed25519 !non-base64!\n",
    "master-key-ed25519 AQ==\n",
])
def test_identita_descrittore_campo_mancante_duplicato_o_non_valido(campo):
    identita = base64.b64decode(IDENTITA + "=" * (-len(IDENTITA) % 4))
    with pytest.raises(ValueError):
        verifica_identita_descrittore(campo, identita)
