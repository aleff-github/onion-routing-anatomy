# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import hashlib
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from torlab.canale import (CERT_IDENTITY_V_SIGNING, CERT_SIGNING_V_TLS_CERT, ErroreCanale,
                           cella_netinfo_client, decodifica_cert_ed, decodifica_certs, decodifica_netinfo,
                           verifica_identita_responder)


def pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def cert_ed(tipo, chiave_certificata, firmataria, includi_firmataria=False, ore=None, tipo_chiave=1):
    ore = int(time.time() // 3600) + 24 if ore is None else ore
    est = b""
    n = 0
    if includi_firmataria:
        est = struct.pack(">HBB", 32, 4, 0) + pub(firmataria)
        n = 1
    corpo = struct.pack(">BBIB", 1, tipo, ore, tipo_chiave) + chiave_certificata + bytes([n]) + est
    return corpo + firmataria.sign(corpo)


def cella_certs(certs):
    corpo = bytes([len(certs)])
    for tipo, c in certs.items():
        corpo += struct.pack(">BH", tipo, len(c)) + c
    return corpo


@pytest.fixture
def catena():
    identita, firma = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    cert_tls = b"certificato TLS di prova"
    certs = {
        CERT_IDENTITY_V_SIGNING: cert_ed(4, pub(firma), identita, includi_firmataria=True),
        CERT_SIGNING_V_TLS_CERT: cert_ed(5, hashlib.sha256(cert_tls).digest(), firma, tipo_chiave=3),
    }
    return identita, firma, cert_tls, certs


def test_catena_valida(catena):
    identita, _, cert_tls, certs = catena
    assert verifica_identita_responder(decodifica_certs(cella_certs(certs)), cert_tls) == pub(identita)


def test_certificato_tls_diverso(catena):
    _, _, _, certs = catena
    with pytest.raises(ErroreCanale, match="TLS"):
        verifica_identita_responder(certs, b"un altro certificato")


def test_firma_alterata(catena):
    _, _, cert_tls, certs = catena
    c = bytearray(certs[CERT_SIGNING_V_TLS_CERT])
    c[-1] ^= 1
    certs[CERT_SIGNING_V_TLS_CERT] = bytes(c)
    with pytest.raises(ErroreCanale, match="firma"):
        verifica_identita_responder(certs, cert_tls)


def test_chiave_di_firma_non_certificata(catena):
    identita, _, cert_tls, certs = catena
    intrusa = Ed25519PrivateKey.generate()
    certs[CERT_SIGNING_V_TLS_CERT] = cert_ed(5, hashlib.sha256(cert_tls).digest(), intrusa)
    with pytest.raises(ErroreCanale, match="firma"):
        verifica_identita_responder(certs, cert_tls)


def test_certificato_scaduto(catena):
    identita, firma, cert_tls, certs = catena
    certs[CERT_SIGNING_V_TLS_CERT] = cert_ed(5, hashlib.sha256(cert_tls).digest(), firma,
                                             ore=int(time.time() // 3600) - 1)
    with pytest.raises(ErroreCanale, match="scaduto"):
        verifica_identita_responder(certs, cert_tls)


def test_certificati_duplicati():
    corpo = bytes([2]) + struct.pack(">BH", 4, 1) + b"x" + struct.pack(">BH", 4, 1) + b"y"
    with pytest.raises(ErroreCanale):
        decodifica_certs(corpo)


def test_netinfo_client():
    cella = cella_netinfo_client("127.0.0.1")
    assert cella.corpo == bytes.fromhex("00000000" "04" "04" "7f000001" "00")
    ni = decodifica_netinfo(cella.corpo.ljust(509, b"\x00"))
    assert (ni.orario, ni.tuo_indirizzo, ni.miei_indirizzi) == (0, "127.0.0.1", [])

def test_truncated_channel_documents():
    # Rifiutare intestazioni troncate e certificati incompleti senza eccezioni di struct.
    for malformed in (b"", b"\x01", b"\x01\x04\x00"):
        with pytest.raises(ErroreCanale):
            decodifica_certs(malformed)
    with pytest.raises(ErroreCanale):
        decodifica_cert_ed(b"\x01" + b"\x00" * 38 + b"\x01" + b"\x00" * 64)
    for malformed in (b"", b"\x00\x00\x00\x00"):
        with pytest.raises(ErroreCanale):
            decodifica_netinfo(malformed)


def test_tipo_certificato_incoerente(catena):
    _, _, cert_tls, certs = catena
    # Il tipo della voce CERTS resta 4, ma il campo tipo coperto dalla firma viene alterato a 5.
    original = bytearray(certs[4])
    original[1] = 5
    certs[4] = bytes(original)
    with pytest.raises(ErroreCanale):
        verifica_identita_responder(certs, cert_tls)

# Controlli offline del circuito: non richiedono un relay né una connessione TLS.
def test_circuit_id_validation():
    from torlab.circuito import Circuito, ErroreCircuito
    for bad in (0, 1, 0x7FFFFFFF, 0x100000000):
        with pytest.raises(ErroreCircuito):
            Circuito(None, bad)
    assert Circuito(None, 0x80000000).circ_id == 0x80000000


def test_circuit_empty_path_and_bad_sendme_increment():
    from torlab.circuito import Circuito, ErroreCircuito, costruisci
    with pytest.raises(ErroreCircuito):
        costruisci([])
    circ = Circuito(None, 0x80000001)
    for extensions in ([(2, b"")], [(2, b"\x00")], [(2, b"\x01\x02")],
                       [(2, b""), (2, b"\x64")]):
        circ.estensioni_exit = extensions
        with pytest.raises(ErroreCircuito):
            circ.conta_data_ricevuto()


def test_circuit_create_rejects_foreign_circid(monkeypatch):
    import torlab.circuito as circuito
    from torlab.celle import Cella, Comando
    from types import SimpleNamespace

    class CanaleFittizio:
        def invia(self, _):
            pass

        def ricevi(self):
            return Cella(0x80000002, Comando.CREATED2)

    monkeypatch.setattr(circuito, "ntor3_client_inizio", lambda *args: (None, b""))
    relay = SimpleNamespace(id_ed=bytes(32), ntor=bytes(32))
    with pytest.raises(circuito.ErroreCircuito, match="CircID"):
        circuito.Circuito(CanaleFittizio(), 0x80000001).crea(relay)
