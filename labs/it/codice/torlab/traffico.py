# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 12 — leggere le celle di un canale catturato e decifrato.

Si parte dall'output di `tshark -q -z follow,tls,raw,N` su una cattura del *proprio*
canale, decifrata con le chiavi esportate tramite SSLKEYLOGFILE (capitolo 20).
Il risultato richiede una cattura comprensiva di entrambe le celle VERSIONS.
"""
from __future__ import annotations

import struct

from .celle import Cella, Comando, ErroreCella, decodifica, negozia_versione


def _versioni(corpo: bytes) -> list[int]:
    if not corpo or len(corpo) % 2:
        raise ErroreCella("VERSIONS con corpo vuoto o di lunghezza dispari")
    return [v for (v,) in struct.iter_unpack(">H", corpo)]


def celle_da_follow(testo: str) -> list[tuple[str, Cella, int]]:
    """Restituisce (verso, cella, versione usata nel parsing).

    L'output tshark deve iniziare col blocco VERSIONS del client.
    La versione di collegamento e' UNICA: e' la maggiore comune alle offerte
    dei due peer; prima della negoziazione ciascuna VERSIONS usa CircID a 2 byte.
    Il parser e' didattico e non sostituisce un dissector TLS/Tor generico.
    """
    righe = [r for r in testo.splitlines()
             if r.strip() and not r.startswith(("=", "Follow", "Filter", "Node"))]
    if not righe:
        return []
    rientro_client = righe[0].startswith("\t")
    versione = {"client": 0, "relay": 0}
    offerte: dict[str, bytes] = {}
    resto = {"client": b"", "relay": b""}
    uscita = []

    for r in righe:
        verso = "client" if r.startswith("\t") == rientro_client else "relay"
        resto[verso] += bytes.fromhex(r.strip())
        while True:
            # Non provare a decodificare celle post-VERSIONS prima di
            # conoscere la versione condivisa da entrambi i peer.
            if verso in offerte and len(offerte) < 2:
                break
            x = decodifica(resto[verso], versione[verso])
            if x is None:
                break
            cella, resto[verso] = x
            if not offerte and (verso != "client" or cella.comando != Comando.VERSIONS):
                raise ErroreCella("il primo blocco non e' VERSIONS del client")
            if cella.comando == Comando.VERSIONS:
                if verso in offerte:
                    raise ErroreCella("VERSIONS duplicata per lo stesso verso")
                offerte[verso] = cella.corpo
                _versioni(cella.corpo)
                uscita.append((verso, cella, 0))
                if len(offerte) == 2:
                    versione_comune = negozia_versione(
                        _versioni(offerte["client"]), offerte["relay"])
                    versione = {"client": versione_comune, "relay": versione_comune}
                continue
            if len(offerte) < 2:
                raise ErroreCella("cella dati prima della negoziazione di VERSION")
            uscita.append((verso, cella, versione[verso]))

    if len(offerte) != 2:
        raise ErroreCella("cattura incompleta: mancano le due celle VERSIONS")
    if any(resto.values()):
        # Resti possono essere segmenti di TLS non ancora consegnati in una cattura
        # troncata; non chiamarli celle complete.
        raise ErroreCella("cattura incompleta: byte Tor residui non decodificati")
    return uscita
