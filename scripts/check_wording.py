#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Cerca i *residui* delle correzioni: formulazioni vecchie rimaste in giro.

Quando si corregge un'affermazione in un capitolo, la stessa affermazione può
comparire altrove — in un altro capitolo, in un esercizio, in una soluzione, in
una figura, nella wiki, in un commento del codice o in un controllo automatico.
Correggerne una e dimenticare le altre è successo davvero (la soluzione 19.5
contraddiceva la 12.7 per un intero giro di revisione).

Questo controllo tiene l'elenco delle formulazioni che NON devono più comparire
da nessuna parte, con il motivo e la forma giusta. Ogni correzione fatta in
revisione va aggiunta qui: è l'unico modo perché un residuo non sopravviva.

Uso: python3 scripts/check_wording.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent

# Cartelle e suffissi in cui cercare: tutto ciò che il lettore può leggere.
AREE = [("source/it/capitoli", ".tex"), ("source/it/appendici", ".tex"), ("source/it/figure", ".tex"),
        ("labs/it/wiki", ".md"), ("labs/it/codice/torlab", ".py"), ("scripts", ".py"), ("labs/it/laboratorio", ".py")]

# Righe in cui una formulazione vietata è citata *apposta* per spiegare che è sbagliata.
# Se una di queste parole compare nella riga del riscontro o in una delle due adiacenti,
# la segnalazione viene soppressa: una spiegazione spesso va a capo, e cercarla solo
# sulla riga del riscontro ha già prodotto un falso positivo. Il prezzo è che una
# formulazione vietata accanto a una di queste parole non viene segnalata.
SPIEGAZIONI = re.compile(r"è un errore|sbagliat|non è vero|errata|sbaglia|sfasat|sopprim")

# (etichetta, espressione regolare del residuo, perché è sbagliato / forma giusta)
RESIDUI: list[tuple[str, str, str]] = [
    ("AUD-004 guard",      r"usano un solo guard|usa un solo guard",
     "i client usano due guard (guard-n-primary-guards-to-use=2)"),
    ("AUD-012 vanguards",  r"1 e 22 giorni|in media circa due settimane",
     "tor 0.4.9.13 usa 1-12 giorni (media ~1 settimana); 1-22 è il valore della spec"),
    ("AUD-021 consenso",   r"non (?:riescono|possono|può) più (?:a )?costruire (?:nuovi )?circuit",
     "il consenso scaduto resta reasonably-live per ~24 ore"),
    ("AUD-027 rollover",   r"\b10136\b",
     "il campo conta le ore: il rollover è fra centinaia di migliaia di anni"),
    ("AUD-029 chiavi aut", r"identità sia di almeno 2048",
     "KP_auth_id_rsa richiede almeno 3072 bit"),
    ("AUD-030 certificato", r"581 byte",
     "la lunghezza del certificato varia da relay a relay (CN casuale)"),
    ("AUD-020 campione",   r"20\\,\\% della banda|20% della banda",
     "il campione è al 20% del NUMERO dei guard, non della banda"),
    ("AUD-034 SOCKS",      r"sempre isolate",
     "isolate per impostazione predefinita, salvo SessionGroup"),
    ("AUD-002 XON",        r"in kilobit al secondo",
     "kbps_ewma è in unità di 1000 byte/sec (proposta 324)"),
    ("AUD-002 PROTOCOLINFO", r"l'unico comando ammesso",
     "anche AUTHCHALLENGE, AUTHENTICATE e QUIT sono ammessi prima dell'auth"),
    ("AUD-003 Stem",       r"thread separato per ogni evento",
     "Stem usa un solo thread per gli eventi, in sequenza"),
    ("AUD-016 CGO",        r"chiave \$K\$ e un valore \$N\$ di 16 byte",
     "K è di 64 byte (KLEN_UIV), N di 16"),
    ("AUD-017 params",     r"votati dalla maggioranza di tutte le autorità",
     "maggioranza OPPURE almeno tre autorità"),
    ("AUD-022 Valid",      r"e solo se ha il flag \\texttt\{Running\}",
     "servono Running E Valid (consensus method 24+)"),
    ("AUD-033 padding",    r"già usati per traffico|canale nuovo e inutilizzato",
     "serve un circuito COMPLETO; con nf_pad_before_usage=1 parte prima del traffico"),
    ("AUD-032 rimando",    r"padding a livello di canale e di circuito\) sono discusse nel \\cref\{cap:15-dos\}",
     "il padding è nei capitoli 7 e 26, non nel 15"),
    ("AUD-009 clearnet",   r"fa uscire i visitatori dalla rete Tor",
     "in Tor Browser il traffico resta in Tor e passa da un exit"),
    ("AUD-015 descrittori", r"per il periodo corrente e per il successivo",
     "i due periodi dipendono dalla posizione nel ciclo SRV/TP"),
    ("AUD-028 integrità",  r"SHA-256, SHA-3, HMAC, Poly1305",
     "il digest dei relay è SHA-1/SHA3-256; POLYVAL per CGO"),
    ("AUD-006 prefazione", r"nell'capitolo|nell’capitolo",
     "gli appendici si citano come «appendice» (tipo cleveref)"),
    ("Lab 19 vecchio",     r"\b9,6\\,?\\?%|9\.6%",
     "il valore corretto con i guard confermati è 18,4%"),
    # NB: `v Tor 0.4.9.12` NON è vietato. Il cap. 12 lo riporta a ragione, perché
    # cita il consenso conservato in labs/it/codice/torlab/test/dati/, catturato quando il
    # laboratorio eseguiva quella versione; vietarlo mi ha fatto introdurre un errore.
    # Vietato è solo il banner di una ESECUZIONE presentata come attuale.
    ("versione laboratorio", r"0\.4\.9\.12 \(git-",
     "la rete di laboratorio esegue tor 0.4.9.13: un banner 0.4.9.12 è un output vecchio"),
    ("numero di controlli", r"sono diventati 40|40 controlli|18 controlli su|\b51 test\b",
     "i controlli dal vivo sono 53 (+6 sul bridge) e i test del codice 53"),
    ("rimando XON/XOFF",   r"limitando la frequenza dei messaggi XON e XOFF\. Ne riparleremo",
     "il cap. 26 non tratta i canali laterali del controllo di flusso: rimando riformulato"),
    ("numero di pagine",   r"\b27[0-9] pagine\b|\b28[0-1] pagine\b",
     "la composizione attuale è di 282 pagine (PIANO.md, proposta.tex)"),
    ("AUD-026 ML-KEM",     r"\(1184 ?\+ ?1088\)|1088\)/498",
     "chiave pubblica e testo cifrato viaggiano in direzioni opposte: 3+3=6 celle, "
     "non si sommano; con la proposta 340 il corpo è 493 byte, non 498"),
]

# Singoli file da controllare oltre alle aree. Non c'è tutta `docs/`: il diario e i
# verdetti degli audit citano di proposito le formulazioni vecchie, per registrare
# ciò che era vero — o sbagliato — il giorno in cui sono stati scritti.
FILE_EXTRA = ["README.md", "README.it.md"]


def da_controllare() -> list[Path]:
    """Tutti i file leggibili dal lettore, più i documenti del repository."""
    elenco = []
    for cartella, suffisso in AREE:
        base = RADICE / cartella
        if base.is_dir():
            elenco += [f for f in sorted(base.rglob(f"*{suffisso}"))
                       if f.name != Path(__file__).name]   # qui i residui ci stanno apposta
    elenco += [RADICE / n for n in FILE_EXTRA if (RADICE / n).is_file()]
    return elenco


def main() -> None:
    problemi = 0
    controllati = 0
    for f in da_controllare():
        testo = f.read_text(errors="replace")
        controllati += 1
        for etichetta, pattern, corretto in RESIDUI:
            for m in re.finditer(pattern, testo):
                riga = testo.count("\n", 0, m.start()) + 1
                righe = testo.splitlines()
                intorno = "\n".join(righe[max(0, riga - 2):riga + 1])
                if SPIEGAZIONI.search(intorno):
                    continue            # citata per spiegare che è sbagliata
                print(f"{f.relative_to(RADICE)}:{riga}: [{etichetta}] «{m.group()[:60]}»")
                print(f"    -> {corretto}")
                problemi += 1
    print(f"\n{controllati} file controllati, {len(RESIDUI)} formulazioni vietate.")
    print("Nessun residuo." if not problemi else f"{problemi} residui da correggere.")
    sys.exit(1 if problemi else 0)


if __name__ == "__main__":
    main()
