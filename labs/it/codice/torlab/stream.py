# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 5 — stream e controllo di flusso.

Riferimenti: tor-spec, "Opening streams and transmitting data", "Closing streams",
"Flow control"; proposta 324 (controllo della congestione, SENDME e XON/XOFF).
Il circuito ha negoziato il controllo della congestione con l'exit: niente SENDME
di stream; i SENDME di circuito in uscita sono emessi da Circuito.conta_data_ricevuto().
Modulo didattico: solo per la rete privata del libro.
Modulo didattico a stream singolo: non gestisce multiplexing, finestra di invio
né verifica i SENDME di circuito in ingresso; non è un client Tor completo.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

from .celle import RELAY_DATA_MAX, ComandoRelay, MessaggioRelay
from .circuito import Circuito, ErroreCircuito

MOTIVI_END = {1: "MISC", 2: "RESOLVEFAILED", 3: "CONNECTREFUSED", 4: "EXITPOLICY",
              5: "DESTROY", 6: "DONE", 7: "TIMEOUT", 8: "NOROUTE", 9: "HIBERNATING",
              10: "INTERNAL", 11: "RESOURCELIMIT", 12: "CONNRESET", 13: "TORPROTOCOL",
              14: "NOTDIRECTORY"}


def corpo_begin(indirizzo: str, porta: int, flag: int = 0) -> bytes:
    """ADDRPORT ASCII con terminatore NUL; FLAGS opzionale (solo bit 1–3)."""
    if not isinstance(indirizzo, str) or not indirizzo or "\x00" in indirizzo:
        raise ValueError("Indirizzo vuoto, non testuale o contenente NUL")
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in indirizzo):
        raise ValueError("Indirizzo con caratteri di controllo o spazi")
    try:
        indirizzo.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("ADDRPORT deve essere ASCII (per i domini internazionali usare IDNA)") from exc
    if ":" in indirizzo or "[" in indirizzo or "]" in indirizzo:
        if not (indirizzo.startswith("[") and indirizzo.endswith("]")):
            raise ValueError("L'indirizzo IPv6 deve essere racchiuso tra parentesi quadre")
        try:
            ipaddress.IPv6Address(indirizzo[1:-1])
        except ValueError as exc:
            raise ValueError("Indirizzo IPv6 non valido") from exc
    if type(porta) is not int or not 1 <= porta <= 65535:
        raise ValueError("La porta deve essere un intero tra 1 e 65535")
    if type(flag) is not int or not 0 <= flag <= 7:
        raise ValueError("FLAGS deve contenere solo i bit 1–3")
    corpo = f"{indirizzo.lower()}:{porta}".encode("ascii") + b"\x00"
    if flag:
        corpo += struct.pack(">I", flag)
    if len(corpo) > RELAY_DATA_MAX:
        raise ValueError("Il corpo BEGIN supera la dimensione massima RELAY")
    return corpo


def _end_reason(data: bytes) -> str:
    reason = data[0] if data else 1   # Un RELAY_END vuoto equivale a REASON_MISC.
    return MOTIVI_END.get(reason, f"SCONOSCIUTO({reason})")


@dataclass
class Registro:
    dati_ricevuti: int = 0
    celle_data: int = 0
    altri: list[str] = field(default_factory=list)


class Stream:
    def __init__(self, circ: Circuito, stream_id: int):
        if type(stream_id) is not int or not 1 <= stream_id <= 65535:
            raise ErroreCircuito("StreamID deve essere un intero non nullo di 16 bit")
        self.circ, self.id = circ, stream_id
        self.reg = Registro()
        self.chiuso = False
        self.aperto = False

    def apri(self, indirizzo: str, porta: int) -> bytes:
        if self.chiuso or self.aperto:
            raise ErroreCircuito("stream già aperto o chiuso")
        self.circ.invia(MessaggioRelay(ComandoRelay.BEGIN, self.id, corpo_begin(indirizzo, porta)))
        while True:
            _, msg = self._prossimo()
            if msg.comando == ComandoRelay.DROP:
                continue
            if msg.comando == ComandoRelay.END:
                self.chiuso = True
                raise ErroreCircuito(f"BEGIN rifiutato: {_end_reason(msg.dati)}")
            if msg.comando != ComandoRelay.CONNECTED:
                raise ErroreCircuito(f"risposta inattesa a BEGIN: {msg.comando}")
            self.aperto = True
            return msg.dati

    def invia(self, dati: bytes) -> None:
        if self.chiuso or not self.aperto:
            raise ErroreCircuito("impossibile inviare dati su uno stream non aperto o chiuso")
        if not isinstance(dati, (bytes, bytearray, memoryview)):
            raise TypeError("I dati devono essere bytes o simili")
        dati = bytes(dati)
        for i in range(0, len(dati), RELAY_DATA_MAX):
            self.circ.invia(MessaggioRelay(ComandoRelay.DATA, self.id, dati[i:i + RELAY_DATA_MAX]))

    def ricevi_tutto(self) -> bytes:
        """Legge DATA fino a END; contabilizza SENDME di circuito in uscita."""
        if not self.aperto:
            raise ErroreCircuito("lo stream non è aperto")
        parts = []
        while not self.chiuso:
            _, msg = self._prossimo()
            if msg.comando == ComandoRelay.DATA:
                parts.append(msg.dati)
                self.reg.dati_ricevuti += len(msg.dati)
                self.reg.celle_data += 1
                self.circ.conta_data_ricevuto()
            elif msg.comando == ComandoRelay.END:
                self.chiuso = True
                self.reg.altri.append(f"END {_end_reason(msg.dati)}")
            elif msg.comando == ComandoRelay.DROP:
                continue
            else:
                known = ComandoRelay._value2member_map_.get(msg.comando)
                self.reg.altri.append(known.name if known else f"SCONOSCIUTO_{msg.comando}")
        return b"".join(parts)

    def _prossimo(self):
        hop, msg = self.circ.ricevi()
        if msg.stream_id == 0:
            if msg.comando == ComandoRelay.DROP:
                return hop, msg
            if msg.comando == ComandoRelay.SENDME:
                # Non elaborare SENDME in ingresso senza controllo della finestra e digest.
                raise ErroreCircuito("SENDME di circuito in ingresso: gestione della finestra di invio non implementata")
            raise ErroreCircuito(f"comando di controllo sul circuito non previsto: {msg.comando}")
        if msg.stream_id != self.id:
            raise ErroreCircuito(f"messaggio per uno stream sconosciuto {msg.stream_id}")
        return hop, msg

    def chiudi(self) -> None:
        if not self.chiuso:
            if not self.aperto:
                raise ErroreCircuito("lo stream non è aperto")
            self.circ.invia(MessaggioRelay(ComandoRelay.END, self.id, bytes([6])))  # DONE
            self.chiuso = True
