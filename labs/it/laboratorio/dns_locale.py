# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Resolver DNS minimo della rete privata (Laboratorio 18).

Gli exit della rete Chutney risolvono i nomi con il file indicato da
ServerDNSResolvConfFile; per la rete del libro è dns_locale.conf, che punta qui:
127.0.0.1, porta 5300. Il resolver:
- ascolta solo su 127.0.0.1 (UDP), mai su altre interfacce;
- risponde in modo deterministico ai soli nomi di NOMI (record A, classe IN);
- per ogni altro nome risponde NXDOMAIN, senza inoltrare nulla a resolver esterni;
- registra le domande ricevute, così il laboratorio può mostrare che la risoluzione
  è avvenuta davvero all'exit.
Senza questo resolver gli exit non risolvono alcun nome (la rete non ne ha bisogno:
tutti i nodi usano indirizzi IP).
"""
from __future__ import annotations

import socket
import struct
import threading

INDIRIZZO, PORTA = "127.0.0.1", 5300
NOMI = {"localhost": "127.0.0.1"}

TIPO_A, CLASSE_IN = 1, 1
NOERROR, FORMERR, NXDOMAIN, NOTIMP = 0, 1, 3, 4


def _leggi_nome(pacchetto: bytes, pos: int) -> tuple[str, int]:
    """Nome della domanda (senza compressione, che nelle domande non si usa)."""
    etichette = []
    while True:
        if pos >= len(pacchetto):
            raise ValueError("nome troncato")
        lung = pacchetto[pos]
        pos += 1
        if lung == 0:
            return ".".join(etichette), pos
        if lung > 63 or pos + lung > len(pacchetto):
            raise ValueError("etichetta non valida")
        etichette.append(pacchetto[pos:pos + lung].decode("ascii").lower())
        pos += lung


def risposta(domanda: bytes, nomi: dict[str, str] = NOMI) -> tuple[bytes | None, str]:
    """Risposta a un pacchetto di domanda; (None, motivo) se non merita risposta."""
    if len(domanda) < 12:
        return None, "pacchetto troppo corto"
    ident, flag, qd, an, ns, ar = struct.unpack(">HHHHHH", domanda[:12])
    if flag & 0x8000:
        return None, "non è una domanda"
    opcode = (flag >> 11) & 0xF
    rd = flag & 0x0100
    testa = lambda rcode, n_risposte: struct.pack(
        ">HHHHHH", ident, 0x8000 | (opcode << 11) | 0x0400 | rd | rcode, 1, n_risposte, 0, 0)
    if qd != 1 or opcode != 0:
        return struct.pack(">HHHHHH", ident, 0x8000 | (opcode << 11) | rd | NOTIMP, 0, 0, 0, 0), "non supportata"
    try:
        nome, fine = _leggi_nome(domanda, 12)
        tipo, classe = struct.unpack(">HH", domanda[fine:fine + 4])
    except (ValueError, UnicodeDecodeError, struct.error):
        return struct.pack(">HHHHHH", ident, 0x8000 | rd | FORMERR, 0, 0, 0, 0), "malformata"
    sezione = domanda[12:fine + 4]
    if nome not in nomi:
        return testa(NXDOMAIN, 0) + sezione, f"{nome} NXDOMAIN"
    if tipo != TIPO_A or classe != CLASSE_IN:
        return testa(NOERROR, 0) + sezione, f"{nome} tipo {tipo}: nessun record"
    record = struct.pack(">HHHIH", 0xC00C, TIPO_A, CLASSE_IN, 60, 4) + socket.inet_aton(nomi[nome])
    return testa(NOERROR, 1) + sezione + record, f"{nome} A {nomi[nome]}"


class ResolverLocale:
    """Il resolver come context manager: thread avviato all'ingresso, chiuso all'uscita."""

    def __init__(self, porta: int = PORTA, nomi: dict[str, str] | None = None):
        self.nomi = dict(NOMI if nomi is None else nomi)
        self.domande: list[str] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.bind((INDIRIZZO, porta))
        except OSError:
            self._sock.close()
            raise
        self._sock.settimeout(0.2)
        self._fermo = threading.Event()
        self._thread = threading.Thread(target=self._servi, name="dns-locale", daemon=True)

    @property
    def porta(self) -> int:
        return self._sock.getsockname()[1]

    def _servi(self) -> None:
        while not self._fermo.is_set():
            try:
                domanda, mittente = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            pacchetto, motivo = risposta(domanda, self.nomi)
            self.domande.append(motivo)
            if pacchetto is not None:
                try:
                    self._sock.sendto(pacchetto, mittente)
                except OSError:
                    pass

    def __enter__(self) -> "ResolverLocale":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.chiudi()

    def chiudi(self) -> None:
        self._fermo.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)
        self._sock.close()
