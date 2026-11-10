# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Un circuito completo del client: canale, CircID e cifratura a strati insieme.

Riunisce i Laboratori 1-4 in un'unica classe usata dai laboratori successivi.
Modulo didattico: solo per la rete privata del libro.
"""
from __future__ import annotations

import os
import struct

from .canale import Canale, apri_canale
from .celle import Cella, Comando, ComandoRelay, MessaggioRelay
from .cifratura import CircuitoClient, ErroreCella, Salto
from .laboratorio import InfoRelay
from .ntor import (HTYPE_NTOR_V3, ChiaviCircuito, codifica_estensioni, corpo_create2,
                   corpo_extend2, decodifica_estensioni, hdata_created2,
                   ntor3_client_fine, ntor3_client_inizio)

MAX_RELAY_EARLY = 8     # MAX_RELAY_EARLY_CELLS_PER_CIRCUIT in tor


class ErroreCircuito(Exception):
    pass


class Circuito:
    def __init__(self, canale: Canale, circ_id: int | None = None):
        self.canale = canale
        # Chi ha aperto il canale usa CircID con il bit più significativo a 1.
        self.circ_id = (0x80000000 | (int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF)) if circ_id is None else circ_id
        if not isinstance(self.circ_id, int) or not 0x80000000 <= self.circ_id <= 0xFFFFFFFF:
            raise ErroreCircuito("CircID del client non valido: richiede bit più significativo a 1")
        self.cripto = CircuitoClient()
        self.relay_early_inviate = 0
        self.estensioni_exit: list[tuple[int, bytes]] = []
        # Celle DATA ricevute dall'ultimo salto e non ancora confermate con un SENDME.
        # Il conteggio è per circuito, non per stream (tor-spec, "Circuit-level flow control").
        self.data_da_confermare = 0
        self.sendme_inviati = 0

    # --- invio e ricezione di messaggi relay -------------------------------
    def invia(self, msg: MessaggioRelay, salto: int | None = None, early: bool = False) -> None:
        """Invia un messaggio al salto indicato (predefinito: l'ultimo).
        early=True usa una cella RELAY_EARLY, obbligatoria per EXTEND2."""
        comando = Comando.RELAY_EARLY if early else Comando.RELAY
        if early:
            if self.relay_early_inviate >= MAX_RELAY_EARLY:
                raise ErroreCircuito("limite di celle RELAY_EARLY raggiunto")
            self.relay_early_inviate += 1
        self.canale.invia(Cella(self.circ_id, comando, self.cripto.cifra(msg, salto)))

    def conta_data_ricevuto(self) -> None:
        """Da chiamare per ogni cella DATA ricevuta dall'ultimo salto: invia un SENDME
        autenticato (versione 1) ogni `sendme_inc` celle."""
        # Per estensioni duplicate conta solo la prima occorrenza (tor-spec).
        response_data = next((data for kind, data in self.estensioni_exit if kind == 2), None)
        sendme_inc = 100 if response_data is None else (response_data[0] if len(response_data) == 1 else 0)
        if sendme_inc is None or sendme_inc == 0:
            raise ErroreCircuito("valore sendme_inc della risposta di congestione non valido")
        self.data_da_confermare += 1
        if self.data_da_confermare == sendme_inc:
            # Il digest è quello progressivo dopo l'ultima cella riconosciuta (quella che
            # fa scattare il SENDME): sendme_digest in src/core/crypto/relay_crypto_tor1.c.
            digest = self.cripto.salti[-1].indietro.digest.digest()
            corpo = struct.pack(">BH", 1, 20) + digest
            self.invia(MessaggioRelay(ComandoRelay.SENDME, 0, corpo))
            self.data_da_confermare = 0
            self.sendme_inviati += 1

    def ricevi(self) -> tuple[int, MessaggioRelay]:
        """Attende il prossimo messaggio relay di questo circuito (ignora il padding)."""
        while True:
            cella = self.canale.ricevi()
            if cella.comando in (Comando.PADDING, Comando.VPADDING):
                continue
            if cella.circ_id != self.circ_id:
                continue                                  # altri circuiti sullo stesso canale
            if cella.comando == Comando.DESTROY:
                if not cella.corpo:
                    raise ErroreCircuito("DESTROY senza codice motivo")
                raise ErroreCircuito(f"circuito distrutto, motivo {cella.corpo[0]}")
            if cella.comando != Comando.RELAY:
                raise ErroreCircuito(f"cella inattesa {cella.comando}")
            return self.cripto.decifra(cella.corpo)

    # --- costruzione ---------------------------------------------------------
    def crea(self, r: InfoRelay, estensioni=()) -> list[tuple[int, bytes]]:
        st, hd = ntor3_client_inizio(r.id_ed, r.ntor, codifica_estensioni(list(estensioni)))
        self.canale.invia(Cella(self.circ_id, Comando.CREATE2, corpo_create2(HTYPE_NTOR_V3, hd)))
        risposta = self.canale.ricevi()
        while risposta.comando in (Comando.PADDING, Comando.VPADDING):
            risposta = self.canale.ricevi()
        if risposta.circ_id != self.circ_id:
            raise ErroreCircuito("CREATED2 con CircID diverso da quello richiesto")
        if risposta.comando != Comando.CREATED2:
            raise ErroreCircuito(f"CREATE2 rifiutata (comando {risposta.comando})")
        sm, k = ntor3_client_fine(st, hdata_created2(risposta.corpo))
        estensioni_ricevute = decodifica_estensioni(sm)
        self.cripto.salti.append(Salto.da_chiavi(ChiaviCircuito.da_flusso(k)))
        return estensioni_ricevute

    def estendi(self, r: InfoRelay, estensioni=()) -> list[tuple[int, bytes]]:
        st, hd = ntor3_client_inizio(r.id_ed, r.ntor, codifica_estensioni(list(estensioni)))
        corpo = corpo_extend2("127.0.0.1", r.porta, r.id_rsa, r.id_ed, HTYPE_NTOR_V3, hd)
        self.invia(MessaggioRelay(ComandoRelay.EXTEND2, 0, corpo), early=True)
        salto, msg = self.ricevi()
        if salto != len(self.cripto.salti) - 1:
            raise ErroreCircuito("EXTENDED2 ricevuta da un salto inatteso")
        if msg.comando != ComandoRelay.EXTENDED2:
            nome = ComandoRelay._value2member_map_.get(msg.comando)
            raise ErroreCircuito(f"estensione fallita: {nome.name if nome else msg.comando}")
        sm, k = ntor3_client_fine(st, hdata_created2(msg.dati))
        estensioni_ricevute = decodifica_estensioni(sm)
        self.cripto.salti.append(Salto.da_chiavi(ChiaviCircuito.da_flusso(k)))
        return estensioni_ricevute


def costruisci(percorso: list[InfoRelay], cc: bool = True) -> Circuito:
    """Canale verso il primo relay e circuito lungo tutto il percorso.
    Con cc=True chiede all'ultimo salto il controllo della congestione, come fa tor."""
    if not percorso:
        raise ErroreCircuito("percorso del circuito vuoto")
    guard = percorso[0]
    canale = apri_canale("127.0.0.1", guard.porta, identita_attesa=guard.id_ed)
    try:
        circ = Circuito(canale)
        ultimo = len(percorso) - 1
        for i, r in enumerate(percorso):
            est = [(1, b"")] if (cc and i == ultimo) else []
            risposta = circ.crea(r, est) if i == 0 else circ.estendi(r, est)
            if i == ultimo:
                circ.estensioni_exit = risposta
    except BaseException:
        canale.sock.close()
        raise
    return circ
