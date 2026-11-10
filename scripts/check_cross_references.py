#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controlla i rimandi: quelli con etichetta e le promesse in prosa.

Due difetti veri sono nati dallo stesso errore — promettere al lettore che un
argomento si trova altrove, quando altrove non c'è. Il cap. 17 rimandava il
padding al cap. 15, che non contiene la parola; il cap. 11 prometteva di
riparlare dei canali laterali del controllo di congestione nel cap. 26, che
tratta altro. Nessuno dei due errori rompe la compilazione: i riferimenti si
risolvono, semplicemente puntano nel posto sbagliato.

Il controllo fa due cose.

1. **Rimandi con etichetta.** Per ogni ``\\cref`` verso un altro file confronta
   il vocabolario del contesto (le parole lunghe che precedono il rimando) con
   il testo del file bersaglio. Se non c'è nemmeno una parola in comune, il
   rimando è sospetto.

2. **Promesse in prosa.** \\enquote{vedremo}, \\enquote{torneremo},
   \\enquote{abbiamo visto} senza alcun puntatore vicino non sono verificabili
   da un programma: vanno lette. Quelle già esaminate sono elencate in
   ``scripts/data/reviewed-cross-references.txt``; il controllo segnala solo le nuove, o quelle
   la cui frase è cambiata, perché vanno riesaminate.

Uso: python3 scripts/check_cross_references.py [--aggiorna]
     ``--aggiorna`` riscrive l'elenco delle promesse esaminate. Va usato solo
     dopo averle lette una per una: è una firma, non una scorciatoia.
"""
from __future__ import annotations

import hashlib
import re
import sys
import unicodedata
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
ESAMINATE = RADICE / "scripts" / "data" / "reviewed-cross-references.txt"

PROMESSE = re.compile(
    r"((?:vedr|torner|riparler|parler|approfondir|incontrer|scoprir|costruir|user|esaminer|"
    r"descriver|mostrer|analizzer|chiarir|affronter|studier|dedicher|riprender|arriver)[ea]mo\b"
    r"|vedr[àa]\b|rimandiamo\b|pi[uù] avanti\b|nel seguito\b|pi[uù] oltre\b|in seguito\b"
    r"|nel prossimo capitolo\b|nei prossimi capitoli\b|capitolo dedicato\b"
    r"|abbiamo (?:visto|gi[àa] visto|costruito|scritto|incontrato|imparato|descritto|"
    r"analizzato|studiato|usato|preparato)\b|lo abbiamo\b|come sappiamo\b)", re.I)

PUNTATORE = re.compile(r"\\cref|\\Cref|Laboratorio~?\d|\\proposta|\\spec|\\cite|\\ref\{|\\file")

# Parole troppo comuni per dire qualcosa sul contenuto di un capitolo.
STOP = set("""della delle degli dello nella nelle negli sulla sulle sugli come quando questo questa
queste questi quello quella abbiamo vedremo visto viene vengono sezione capitolo appendice
laboratorio essere anche perche quindi invece infatti mentre ancora sempre soltanto solamente
prima dopo stesso stessa stesse stessi altro altra altre altri molto poco tutti tutte tutto tutta
parte possono posso puoi deve devono serve servono trova trovano lettore libro esempio esempi
figura tabella riquadro esercizio esercizi soluzione paragrafo passo passi""".split())


def senza_accenti(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")


def files() -> list[Path]:
    return sorted((RADICE / "source" / "it" / "capitoli").glob("*.tex")) + \
           sorted((RADICE / "source" / "it" / "appendici").glob("*.tex"))


def frase(testo: str, pos: int) -> str:
    """La frase che contiene la posizione data, normalizzata."""
    inizio = max(testo.rfind(". ", 0, pos), testo.rfind("\n", 0, pos)) + 1
    fine = testo.find(". ", pos)
    fine = fine + 1 if fine > 0 else min(len(testo), pos + 200)
    return " ".join(testo[inizio:fine].split())


def impronta(f: str) -> str:
    return hashlib.sha256(senza_accenti(f).lower().encode()).hexdigest()[:12]


def rimandi_sospetti() -> dict[str, str]:
    etichette, testi = {}, {}
    for f in files():
        t = f.read_text()
        testi[f.name] = senza_accenti(t.lower())
        for m in re.finditer(r"\\label\[?\w*\]?\{([^}]+)\}", t):
            etichette[m.group(1)] = f.name
    fuori = set(STOP) | {senza_accenti(w) for w in STOP}
    segnalati = {}
    for f in files():
        t = f.read_text()
        for m in re.finditer(r"\\[Cc]ref\{([^}]+)\}", t):
            for lab in (x.strip() for x in m.group(1).split(",")):
                bersaglio = etichette.get(lab)
                if not bersaglio or bersaglio == f.name:
                    continue
                ctx = re.sub(r"\\[a-zA-Z]+|\{|\}", " ", t[max(0, m.start() - 150):m.start()]).lower()
                parole = {senza_accenti(w) for w in re.findall(r"[a-zàèéìòù]{6,}", ctx)} - fuori
                if len(parole) < 2:
                    continue
                if not any(w[:7] in testi[bersaglio] for w in parole):
                    riga = t.count("\n", 0, m.start()) + 1
                    fr = frase(t, m.start())
                    segnalati[impronta(fr)] = (
                        f"{f.name}:{riga}: rimando a {lab} ({bersaglio}) senza nessuna parola "
                        f"in comune ({', '.join(sorted(parole)[:5])}): {fr[:110]}")
    return segnalati


def promesse() -> dict[str, str]:
    """Promesse in prosa senza puntatore: impronta della frase -> dove si trova."""
    trovate = {}
    for f in files():
        t = f.read_text()
        for m in PROMESSE.finditer(t):
            fr = frase(t, m.start())
            if PUNTATORE.search(fr):
                continue                       # il rimando c'è: lo controlla rimandi_sospetti
            riga = t.count("\n", 0, m.start()) + 1
            trovate[impronta(fr)] = f"{f.name}:{riga}: {fr[:150]}"
    return trovate


def main() -> None:
    aggiorna = "--aggiorna" in sys.argv
    sospetti = rimandi_sospetti()
    attuali = promesse()

    tutte = {**{k: f"PROMESSA {v}" for k, v in attuali.items()},
             **{k: f"RIMANDO  {v}" for k, v in sospetti.items()}}

    if aggiorna:
        ESAMINATE.write_text(
            "# Rimandi letti una per una e accettati: promesse in prosa senza puntatore, e\n"
            "# rimandi con etichetta il cui contesto non ha parole in comune col bersaglio.\n"
            "# La chiave è l'impronta della frase: se la frase cambia, il controllo la ripropone.\n"
            "# Rigenerare con: python3 scripts/check_cross_references.py --aggiorna\n"
            + "".join(f"{k}  {v}\n" for k, v in sorted(tutte.items(), key=lambda x: x[1])))
        print(f"Elenco aggiornato: {len(tutte)} rimandi esaminati.")
        return

    note = {r.split()[0] for r in ESAMINATE.read_text().splitlines()
            if r.strip() and not r.startswith("#")} if ESAMINATE.is_file() else set()
    nuovi = {k: v for k, v in tutte.items() if k not in note}

    for v in sorted(nuovi.values()):
        print(f"da esaminare  {v}")

    print(f"\n{len(files())} file: {len(attuali)} promesse in prosa senza puntatore e "
          f"{len(sospetti)} rimandi senza vocabolario in comune; "
          f"{len(tutte) - len(nuovi)} già esaminati, {len(nuovi)} da esaminare.")
    if nuovi:
        print("Leggi le segnalazioni; se il rimando è mantenuto, registralo con --aggiorna.")
        sys.exit(1)
    print("Nessun rimando a vuoto.")


if __name__ == "__main__":
    main()
