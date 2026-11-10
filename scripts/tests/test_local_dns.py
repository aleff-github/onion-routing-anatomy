# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Resolver DNS locale della rete privata (LV-13): offline, solo loopback."""
from __future__ import annotations

import re
import socket
import struct
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[2] / "labs" / "it" / "laboratorio"
sys.path.insert(0, str(LAB))
import dns_locale as dl  # noqa: E402


def domanda(nome: str, tipo: int = 1, ident: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(e)]) + e.encode() for e in nome.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", tipo, 1)


def chiedi(porta: int, pacchetto: bytes, attesa: float = 2.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(attesa)
        s.sendto(pacchetto, ("127.0.0.1", porta))
        return s.recvfrom(512)[0]


def rcode(r: bytes) -> int:
    return r[3] & 0xF


def risposte(r: bytes) -> int:
    return struct.unpack(">H", r[6:8])[0]


@pytest.fixture
def resolver():
    with dl.ResolverLocale(porta=0) as r:
        yield r


def test_localhost_risolto_in_127_0_0_1(resolver):
    r = chiedi(resolver.porta, domanda("localhost"))
    assert rcode(r) == dl.NOERROR and risposte(r) == 1 and r[-4:] == socket.inet_aton("127.0.0.1")
    assert r[:2] == b"\x12\x34" and r[2] & 0x80                  # stesso id, è una risposta
    assert resolver.domande == ["localhost A 127.0.0.1"]


def test_risposta_deterministica(resolver):
    a = chiedi(resolver.porta, domanda("LOCALHOST", ident=7))
    b = chiedi(resolver.porta, domanda("localhost", ident=7))
    assert a[:2] == b[:2] and a[12:] .lower() == b[12:].lower() and a[2:12] == b[2:12]


def test_altri_nomi_nxdomain_senza_inoltro(resolver, monkeypatch):
    destinazioni = []
    originale = socket.socket.sendto

    def sendto(self, dati, *args):
        destinazioni.append(args[-1])
        return originale(self, dati, *args)

    monkeypatch.setattr(socket.socket, "sendto", sendto)
    for nome in ("example.com", "torproject.org", "localhost.example"):
        r = chiedi(resolver.porta, domanda(nome))
        assert rcode(r) == dl.NXDOMAIN and risposte(r) == 0
    # Ogni pacchetto è partito dal client di prova o è tornato al client: solo loopback.
    assert destinazioni and all(d[0] == "127.0.0.1" for d in destinazioni)


def test_aaaa_senza_record(resolver):
    r = chiedi(resolver.porta, domanda("localhost", tipo=28))
    assert rcode(r) == dl.NOERROR and risposte(r) == 0


def test_pacchetti_malformati():
    assert dl.risposta(b"\x00" * 5)[0] is None
    r, motivo = dl.risposta(struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05abc")
    assert rcode(r) == dl.FORMERR and motivo == "malformata"
    r, _ = dl.risposta(struct.pack(">HHHHHH", 1, 0x0100, 2, 0, 0, 0) + b"\x00" * 10)
    assert rcode(r) == dl.NOTIMP
    assert dl.risposta(domanda("localhost")[:2] + b"\x81\x00" + domanda("localhost")[4:])[0] is None


def test_ascolta_solo_su_loopback(resolver):
    assert resolver._sock.getsockname()[0] == "127.0.0.1"
    assert dl.INDIRIZZO == "127.0.0.1"


def test_avvio_e_arresto_puliti():
    r = dl.ResolverLocale(porta=0)
    porta = r.porta
    with r:
        assert r._thread.is_alive()
    assert not r._thread.is_alive() and r._sock.fileno() == -1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", porta))                              # porta di nuovo libera


def test_arresto_anche_con_eccezione():
    with pytest.raises(RuntimeError):
        with dl.ResolverLocale(porta=0) as r:
            raise RuntimeError("prova interrotta")
    assert not r._thread.is_alive() and r._sock.fileno() == -1


def test_dns_non_disponibile():
    """Senza resolver attivo (come gli exit fuori dal Lab 18) non arriva nessuna risposta."""
    r = dl.ResolverLocale(porta=0)
    porta = r.porta
    r.chiudi()
    with pytest.raises((socket.timeout, ConnectionRefusedError)):
        chiedi(porta, domanda("localhost"), attesa=0.5)


def test_porta_occupata_errore_esplicito():
    with dl.ResolverLocale(porta=0) as r:
        with pytest.raises(OSError):
            dl.ResolverLocale(porta=r.porta)


def test_configurazione_degli_exit():
    righe = [r for r in (LAB / "dns_locale.conf").read_text().splitlines()
             if r.strip() and not r.startswith("#")]
    assert righe == [f"nameserver 127.0.0.1:{dl.PORTA}"]


def test_makefile_passa_dns_conf_e_fuga_dns_usa_il_resolver():
    assert "CHUTNEY_DNS_CONF=/lab/dns_locale.conf" in (LAB / "Makefile").read_text()
    sorgente = (LAB / "fuga_dns.py").read_text()
    assert "from dns_locale import ResolverLocale" in sorgente
    assert re.search(r"with ResolverLocale\(\) as dns", sorgente)
    # Il resolver è attivo prima che gli exit vengano riattivati e prima delle prove.
    assert (sorgente.index("with ResolverLocale() as dns") < sorgente.index("riattiva_resolver_degli_exit()\n")
            < sorgente.index("passed = run_cases("))
