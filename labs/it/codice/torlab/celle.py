# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 2 — codifica e decodifica delle celle Tor.

Riferimenti: tor-spec, "Cells (messages on channels)", "Relay cells",
"Message lengths", "Negotiating versions with VERSIONS cells".
Modulo didattico: privilegia la leggibilità rispetto alle prestazioni.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import IntEnum

CELL_BODY_LEN = 509          # byte di corpo di una cella a lunghezza fissa
RELAY_HEADER_LEN = 11        # intestazione di un messaggio relay (formato tradizionale)
RELAY_DATA_MAX = CELL_BODY_LEN - RELAY_HEADER_LEN   # 498


class Comando(IntEnum):
    """Valori del campo Command (tor-spec, cell-packet-format)."""
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    VERSIONS = 7
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11
    PADDING_NEGOTIATE = 12
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132


class ComandoRelay(IntEnum):
    """Valori del campo Relay command (tor-spec, relay-cells)."""
    BEGIN = 1
    DATA = 2
    END = 3
    CONNECTED = 4
    SENDME = 5
    EXTEND = 6
    EXTENDED = 7
    TRUNCATE = 8
    TRUNCATED = 9
    DROP = 10
    RESOLVE = 11
    RESOLVED = 12
    BEGIN_DIR = 13
    EXTEND2 = 14
    EXTENDED2 = 15
    CONFLUX_LINK = 19
    CONFLUX_LINKED = 20
    CONFLUX_LINKED_ACK = 21
    CONFLUX_SWITCH = 22
    ESTABLISH_INTRO = 32
    ESTABLISH_RENDEZVOUS = 33
    INTRODUCE1 = 34
    INTRODUCE2 = 35
    RENDEZVOUS1 = 36
    RENDEZVOUS2 = 37
    INTRO_ESTABLISHED = 38
    RENDEZVOUS_ESTABLISHED = 39
    INTRODUCE_ACK = 40
    PADDING_NEGOTIATE = 41
    PADDING_NEGOTIATED = 42
    XOFF = 43
    XON = 44


class ErroreCella(ValueError):
    """Cella malformata o non ammessa dal protocollo."""


def circid_len(versione: int) -> int:
    """Lunghezza in byte del CircID: 2 fino al link protocol 3, 4 dal 4 in poi."""
    return 2 if versione < 4 else 4


def lunghezza_variabile(comando: int) -> bool:
    """VERSIONS (7) e tutti i comandi >= 128 hanno lunghezza variabile."""
    return comando == Comando.VERSIONS or comando >= 128


@dataclass
class Cella:
    circ_id: int
    comando: int
    corpo: bytes = b""


def codifica(cella: Cella, versione: int) -> bytes:
    """Serializza una cella per un canale che usa il link protocol `versione`.

    Le celle VERSIONS si codificano sempre con versione 0 (CircID di 2 byte),
    perché al momento dell'invio la versione non è ancora negoziata.
    """
    if cella.comando == Comando.VERSIONS:
        versione = 0
    n = circid_len(versione)
    if not 0 <= cella.circ_id < 1 << (8 * n):
        raise ErroreCella(f"CircID {cella.circ_id:#x} non sta in {n} byte")
    # Il CircID deve corrispondere alla classe di comando prevista da tor-spec.
    if cella.comando in (
        Comando.PADDING, Comando.VERSIONS, Comando.NETINFO, Comando.VPADDING,
        Comando.CERTS, Comando.AUTH_CHALLENGE, Comando.AUTHENTICATE, Comando.AUTHORIZE,
    ) and cella.circ_id != 0:
        raise ErroreCella("questa cella richiede CircID uguale a zero")
    if cella.comando in (
        Comando.CREATE, Comando.CREATED, Comando.RELAY, Comando.DESTROY,
        Comando.CREATE_FAST, Comando.CREATED_FAST, Comando.RELAY_EARLY,
        Comando.CREATE2, Comando.CREATED2, Comando.PADDING_NEGOTIATE,
    ) and cella.circ_id == 0:
        raise ErroreCella("questa cella richiede CircID diverso da zero")
    intestazione = cella.circ_id.to_bytes(n, "big") + bytes([cella.comando])
    if lunghezza_variabile(cella.comando):
        if len(cella.corpo) > 0xFFFF:
            raise ErroreCella("corpo troppo lungo per una cella variabile")
        return intestazione + struct.pack(">H", len(cella.corpo)) + cella.corpo
    if len(cella.corpo) > CELL_BODY_LEN:
        raise ErroreCella(f"corpo di {len(cella.corpo)} byte > {CELL_BODY_LEN}")
    # Riempimento con zeri fino a CELL_BODY_LEN (tor-spec, body-padding).
    return intestazione + cella.corpo.ljust(CELL_BODY_LEN, b"\x00")


def decodifica(buffer: bytes, versione: int) -> tuple[Cella, bytes] | None:
    """Estrae la prima cella da `buffer`.

    Restituisce (cella, byte_rimanenti), oppure None se il buffer non contiene
    ancora una cella completa: i dati TLS arrivano a pezzi di dimensione arbitraria.
    """
    n = circid_len(versione)
    if len(buffer) < n + 1:
        return None
    circ_id = int.from_bytes(buffer[:n], "big")
    comando = buffer[n]
    if lunghezza_variabile(comando):
        if len(buffer) < n + 3:
            return None
        (lunghezza,) = struct.unpack(">H", buffer[n + 1:n + 3])
        fine = n + 3 + lunghezza
        inizio_corpo = n + 3
    else:
        fine = n + 1 + CELL_BODY_LEN
        inizio_corpo = n + 1
    if len(buffer) < fine:
        return None
    return Cella(circ_id, comando, buffer[inizio_corpo:fine]), buffer[fine:]


# --- VERSIONS -----------------------------------------------------------------

def cella_versions(versioni: list[int]) -> Cella:
    """Costruisce una cella VERSIONS: lista di interi big-endian di 2 byte."""
    return Cella(0, Comando.VERSIONS, b"".join(struct.pack(">H", v) for v in versioni))


def negozia_versione(mie: list[int], corpo_ricevuto: bytes) -> int:
    """Sceglie la versione più alta comune (tor-spec, VERSIONS-cells)."""
    if len(corpo_ricevuto) % 2:
        raise ErroreCella("VERSIONS con un numero dispari di byte")
    sue = {v for (v,) in struct.iter_unpack(">H", corpo_ricevuto)}
    comuni = set(mie) & sue
    if not comuni:
        raise ErroreCella("nessuna versione del link protocol in comune")
    return max(comuni)


# --- DESTROY ------------------------------------------------------------------

MOTIVI_DESTROY = ["NONE", "PROTOCOL", "INTERNAL", "REQUESTED", "HIBERNATING",
                  "RESOURCELIMIT", "CONNECTFAILED", "OR_IDENTITY", "CHANNEL_CLOSED",
                  "FINISHED", "TIMEOUT", "DESTROYED", "NOSUCHSERVICE"]


def cella_destroy(circ_id: int, motivo: int = 0) -> Cella:
    """DESTROY: il corpo è un solo byte di motivo; la specifica raccomanda NONE (0)."""
    if circ_id == 0:
        raise ErroreCella("DESTROY richiede un CircID diverso da zero")
    return Cella(circ_id, Comando.DESTROY, bytes([motivo]))


# --- Messaggi relay (formato tradizionale, prima di CGO) ----------------------

@dataclass
class MessaggioRelay:
    comando: int
    stream_id: int
    dati: bytes = b""
    recognized: int = 0
    digest: bytes = b"\x00\x00\x00\x00"


def codifica_relay(msg: MessaggioRelay, casuale=os.urandom) -> bytes:
    """Produce il corpo in chiaro (509 byte) di una cella RELAY.

    Padding: 4 byte a zero seguiti da byte casuali (tor-spec, relay-cell-padding).
    Il digest va calcolato a parte (capitolo 10): qui si usa il valore in `msg`.
    """
    if len(msg.dati) > RELAY_DATA_MAX:
        raise ErroreCella(f"al massimo {RELAY_DATA_MAX} byte di dati per cella")
    intestazione = struct.pack(">BHH4sH", msg.comando, msg.recognized,
                               msg.stream_id, msg.digest, len(msg.dati))
    spazio = CELL_BODY_LEN - RELAY_HEADER_LEN - len(msg.dati)
    padding = b"\x00" * min(4, spazio) + casuale(max(0, spazio - 4))
    return intestazione + msg.dati + padding


def decodifica_relay(corpo: bytes) -> MessaggioRelay:
    """Interpreta il corpo *già decifrato* di una cella RELAY."""
    if len(corpo) != CELL_BODY_LEN:
        raise ErroreCella("il corpo di una cella RELAY è sempre di 509 byte")
    comando, recognized, stream_id, digest, lunghezza = struct.unpack(
        ">BHH4sH", corpo[:RELAY_HEADER_LEN])
    if lunghezza > RELAY_DATA_MAX:
        raise ErroreCella(f"campo Length {lunghezza} > {RELAY_DATA_MAX}")
    dati = corpo[RELAY_HEADER_LEN:RELAY_HEADER_LEN + lunghezza]
    return MessaggioRelay(comando, stream_id, dati, recognized, digest)


def descrivi(cella: Cella, versione: int) -> str:
    """Rappresentazione leggibile di una cella, utile per il debug."""
    try:
        nome = Comando(cella.comando).name
    except ValueError:
        nome = f"SCONOSCIUTO({cella.comando})"
    w = 2 * circid_len(0 if cella.comando == Comando.VERSIONS else versione)
    return f"CircID=0x{cella.circ_id:0{w}x} {nome} corpo={len(cella.corpo)} byte"
