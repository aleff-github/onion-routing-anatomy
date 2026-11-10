# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 4 — la cipolla: cifratura "tor1" dei relay cell.

Riferimenti: tor-spec, "Relay cells" (Recognized, Digest) e "Routing relay cells".
Ogni salto ha, per direzione, un cifrario AES-128-CTR e un digest SHA-1 progressivo:
entrambi mantengono lo stato da una cella all'altra.
Modulo didattico: solo per la rete privata del libro.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .celle import CELL_BODY_LEN, MessaggioRelay, codifica_relay, decodifica_relay
from .ntor import ChiaviCircuito

POS_DIGEST = slice(5, 9)       # byte del campo Digest nel corpo in chiaro
POS_RECOGNIZED = slice(1, 3)


def _aes_ctr(chiave: bytes):
    # IV a zero: il contatore prosegue di cella in cella per tutta la vita del circuito.
    return Cipher(algorithms.AES(chiave), modes.CTR(bytes(16))).encryptor()


def _senza_digest(corpo: bytes) -> bytes:
    return corpo[:5] + bytes(4) + corpo[9:]


@dataclass
class Direzione:
    """Stato di una direzione di un salto: flusso AES e digest progressivo."""
    cifrario: object
    digest: "hashlib._Hash"

    @classmethod
    def nuova(cls, chiave: bytes, seme_digest: bytes) -> "Direzione":
        if len(chiave) != 16 or len(seme_digest) != 20:
            raise ErroreCella("AES-128 richiede una chiave di 16 byte e un seme digest di 20 byte")
        d = hashlib.sha1()
        d.update(seme_digest)
        return cls(_aes_ctr(chiave), d)

    def applica(self, dati: bytes) -> bytes:
        """Cifrare e decifrare coincidono in CTR: XOR con il flusso di chiavi."""
        if len(dati) != CELL_BODY_LEN:
            raise ErroreCella("una cella RELAY cifrata deve contenere esattamente 509 byte")
        return self.cifrario.update(dati)

    def firma(self, corpo: bytes) -> bytes:
        """Aggiorna il digest con la cella (Digest a zero) e scrive i primi 4 byte."""
        if len(corpo) != CELL_BODY_LEN:
            raise ErroreCella("una cella RELAY cifrata deve contenere esattamente 509 byte")
        self.digest.update(_senza_digest(corpo))
        return corpo[:5] + self.digest.digest()[:4] + corpo[9:]

    def riconosce(self, corpo: bytes) -> bool:
        """Recognized a zero e digest corretto; aggiorna lo stato solo se la cella è nostra."""
        if len(corpo) != CELL_BODY_LEN:
            raise ErroreCella("una cella RELAY cifrata deve contenere esattamente 509 byte")
        if corpo[POS_RECOGNIZED] != b"\x00\x00":
            return False
        prova = self.digest.copy()
        prova.update(_senza_digest(corpo))
        if not hmac.compare_digest(prova.digest()[:4], corpo[POS_DIGEST]):
            return False                      # falso positivo di Recognized: ignora
        self.digest = prova
        return True


@dataclass
class Salto:
    """Ciò che client e relay condividono per un salto del circuito."""
    avanti: Direzione
    indietro: Direzione

    @classmethod
    def da_chiavi(cls, k: ChiaviCircuito) -> "Salto":
        return cls(Direzione.nuova(k.Kf, k.Df), Direzione.nuova(k.Kb, k.Db))


class ErroreCella(Exception):
    pass


@dataclass
class CircuitoClient:
    """Lato client: conosce le chiavi di tutti i salti."""
    salti: list[Salto] = field(default_factory=list)

    def cifra(self, msg: MessaggioRelay, destinazione: int | None = None) -> bytes:
        """Prepara il corpo di una cella RELAY per il salto `destinazione` (0 = primo)."""
        if not self.salti:
            raise ErroreCella("il circuito non contiene salti")
        d = len(self.salti) - 1 if destinazione is None else destinazione
        if not isinstance(d, int) or not 0 <= d < len(self.salti):
            raise ErroreCella("indice del salto destinatario non valido")
        corpo = self.salti[d].avanti.firma(codifica_relay(msg))
        for i in range(d, -1, -1):             # strati dal più interno al più esterno
            corpo = self.salti[i].avanti.applica(corpo)
        return corpo

    def decifra(self, corpo: bytes) -> tuple[int, MessaggioRelay]:
        """Toglie gli strati di una cella in arrivo finché un salto la riconosce."""
        if len(corpo) != CELL_BODY_LEN:
            raise ErroreCella("una cella RELAY cifrata deve contenere esattamente 509 byte")
        if not self.salti:
            raise ErroreCella("il circuito non contiene salti")
        for i, salto in enumerate(self.salti):
            corpo = salto.indietro.applica(corpo)
            if salto.indietro.riconosce(corpo):
                return i, decodifica_relay(corpo)
        raise ErroreCella("cella non riconosciuta da nessun salto: circuito da chiudere")


@dataclass
class SaltoRelay:
    """Lato relay (per i test): conosce solo le chiavi del proprio salto."""
    salto: Salto

    def dal_client(self, corpo: bytes) -> tuple[bool, bytes]:
        corpo = self.salto.avanti.applica(corpo)
        return self.salto.avanti.riconosce(corpo), corpo

    def verso_client(self, msg: MessaggioRelay) -> bytes:
        return self.salto.indietro.applica(self.salto.indietro.firma(codifica_relay(msg)))

    def inoltra_verso_client(self, corpo: bytes) -> bytes:
        return self.salto.indietro.applica(corpo)
