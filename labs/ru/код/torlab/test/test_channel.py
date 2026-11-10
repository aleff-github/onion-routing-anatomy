# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import hashlib
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from torlab.channel import (CERT_IDENTITY_V_SIGNING, CERT_SIGNING_V_TLS_CERT, ChannelError,
                           client_netinfo_cell, decode_ed_certificate, decode_certs, decode_netinfo,
                           verify_responder_identity)


def pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def cert_ed(kind, certified_key, signer, include_signer=False, hours=None, key_type=1):
    hours = int(time.time() // 3600) + 24 if hours is None else hours
    est = b""
    n = 0
    if include_signer:
        est = struct.pack(">HBB", 32, 4, 0) + pub(signer)
        n = 1
    body = struct.pack(">BBIB", 1, kind, hours, key_type) + certified_key + bytes([n]) + est
    return body + signer.sign(body)


def certs_cell(certs):
    body = bytes([len(certs)])
    for kind, c in certs.items():
        body += struct.pack(">BH", kind, len(c)) + c
    return body


@pytest.fixture
def chain():
    identity, signature = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    cert_tls = b"test TLS certificate"
    certs = {
        CERT_IDENTITY_V_SIGNING: cert_ed(4, pub(signature), identity, include_signer=True),
        CERT_SIGNING_V_TLS_CERT: cert_ed(5, hashlib.sha256(cert_tls).digest(), signature, key_type=3),
    }
    return identity, signature, cert_tls, certs


def test_valid_chain(chain):
    identity, _, cert_tls, certs = chain
    assert verify_responder_identity(decode_certs(certs_cell(certs)), cert_tls) == pub(identity)


def test_different_tls_certificate(chain):
    _, _, _, certs = chain
    with pytest.raises(ChannelError, match="TLS"):
        verify_responder_identity(certs, b"another certificate")


def test_modified_signature(chain):
    _, _, cert_tls, certs = chain
    c = bytearray(certs[CERT_SIGNING_V_TLS_CERT])
    c[-1] ^= 1
    certs[CERT_SIGNING_V_TLS_CERT] = bytes(c)
    with pytest.raises(ChannelError, match="подпись"):
        verify_responder_identity(certs, cert_tls)


def test_uncertified_signing_key(chain):
    identity, _, cert_tls, certs = chain
    rogue = Ed25519PrivateKey.generate()
    certs[CERT_SIGNING_V_TLS_CERT] = cert_ed(5, hashlib.sha256(cert_tls).digest(), rogue)
    with pytest.raises(ChannelError, match="подпись"):
        verify_responder_identity(certs, cert_tls)


def test_expired_certificate(chain):
    identity, signature, cert_tls, certs = chain
    certs[CERT_SIGNING_V_TLS_CERT] = cert_ed(5, hashlib.sha256(cert_tls).digest(), signature,
                                             hours=int(time.time() // 3600) - 1)
    with pytest.raises(ChannelError, match="просрочен"):
        verify_responder_identity(certs, cert_tls)


def test_duplicate_certificates():
    body = bytes([2]) + struct.pack(">BH", 4, 1) + b"x" + struct.pack(">BH", 4, 1) + b"y"
    with pytest.raises(ChannelError):
        decode_certs(body)


def test_client_netinfo():
    cell = client_netinfo_cell("127.0.0.1")
    assert cell.body == bytes.fromhex("00000000" "04" "04" "7f000001" "00")
    ni = decode_netinfo(cell.body.ljust(509, b"\x00"))
    assert (ni.timestamp, ni.peer_address, ni.my_addresses) == (0, "127.0.0.1", [])

def test_truncated_channel_documents():
    # Усечённые заголовки и сертификаты должны отклоняться управляемой ошибкой.
    for malformed in (b"", b"\x01", b"\x01\x04\x00"):
        with pytest.raises(ChannelError):
            decode_certs(malformed)
    with pytest.raises(ChannelError):
        decode_ed_certificate(b"\x01" + b"\x00" * 38 + b"\x01" + b"\x00" * 64)
    for malformed in (b"", b"\x00\x00\x00\x00"):
        with pytest.raises(ChannelError):
            decode_netinfo(malformed)


def test_certificate_type_does_not_match_certs(chain):
    _, _, cert_tls, certs = chain
    # Тип записи CERTS остаётся равным 4, но поле типа, покрытое подписью сертификата, меняется на 5.
    original = bytearray(certs[4])
    original[1] = 5
    certs[4] = bytes(original)
    with pytest.raises(ChannelError):
        verify_responder_identity(certs, cert_tls)

# Проверки цепочки без сетевых соединений TLS и без действующего ретранслятора.
def test_circuit_id_validation():
    from torlab.circuit import Circuit, CircuitError
    for bad in (0, 1, 0x7FFFFFFF, 0x100000000):
        with pytest.raises(CircuitError):
            Circuit(None, bad)
    assert Circuit(None, 0x80000000).circ_id == 0x80000000


def test_circuit_empty_path_and_bad_sendme_increment():
    from torlab.circuit import Circuit, CircuitError, build
    with pytest.raises(CircuitError):
        build([])
    circ = Circuit(None, 0x80000001)
    for extensions in ([(2, b"")], [(2, b"\x00")], [(2, b"\x01\x02")],
                       [(2, b""), (2, b"\x64")]):
        circ.exit_extensions = extensions
        with pytest.raises(CircuitError):
            circ.count_received_data()


def test_circuit_create_rejects_foreign_circid(monkeypatch):
    import torlab.circuit as circuit
    from torlab.cells import Cell, CellCommand
    from types import SimpleNamespace

    class FakeChannel:
        def send(self, _):
            pass

        def receive(self):
            return Cell(0x80000002, CellCommand.CREATED2)

    monkeypatch.setattr(circuit, "ntor3_client_start", lambda *args: (None, b""))
    relay = SimpleNamespace(id_ed=bytes(32), ntor=bytes(32))
    with pytest.raises(circuit.CircuitError, match="CircID"):
        circuit.Circuit(FakeChannel(), 0x80000001).create(relay)
