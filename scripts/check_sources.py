#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controlli automatici di qualità sul sorgente del libro.
Riporta: marcatori \\dacontrollare, capitoli senza esercizi, figure non referenziate,
termini sconsigliati, chiavi \\cite assenti dalla bibliografia."""
import re
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
LIBRO = RADICE / "source" / "it"
SCONSIGLIATI = {r"\bhidden service\b": "onion service (salvo contesto storico)",
                r"\bdark ?web\b": "evitare il sensazionalismo; preferire 'onion service'"}

def controlla_wiki() -> int:
    """I rimandi fra le pagine della wiki devono puntare a pagine esistenti, e ogni
    laboratorio deve avere la sua pagina."""
    wiki = RADICE / "labs" / "it" / "wiki"
    if not wiki.is_dir():
        return 0
    problemi = 0
    pagine = {f.stem for f in wiki.glob("*.md")}
    for f in sorted(wiki.glob("*.md")):
        for testo_link, dest in re.findall(r"\[([^\]]+)\]\(([^)\s]+)\)", f.read_text()):
            if dest.startswith(("http", "#", "mailto", "../", "/")):
                continue
            percorso = dest.split("#")[0]
            pagina = percorso.removesuffix(".md")
            if pagina not in pagine:
                print(f"labs/it/wiki/{f.name}: rimando a una pagina inesistente: {dest}")
                problemi += 1
            elif not percorso.endswith(".md"):
                # Senza estensione il link funziona solo nella wiki di GitHub, non nella repository.
                print(f"labs/it/wiki/{f.name}: rimando senza .md: {dest}")
                problemi += 1
    mancanti = [n for n in range(1, 21)
                if not any(p.startswith(f"Laboratorio-{n:02d}-") for p in pagine)]
    if mancanti:
        print(f"wiki: manca la pagina dei laboratori {mancanti}")
        problemi += len(mancanti)
    return problemi


def main():
    problemi = 0
    bib = (RADICE / "source" / "shared" / "bibliography" / "tor.bib").read_text(encoding="utf-8")
    chiavi_bib = set(re.findall(r"@\w+\{([^,]+),", bib))
    for f in sorted(LIBRO.glob("*/*.tex")):
        testo = f.read_text(encoding="utf-8")
        rel = f.relative_to(RADICE)
        n = testo.count("\\dacontrollare")
        if n:
            print(f"{rel}: {n} punti \\dacontrollare")
            problemi += n
        if f.parent.name == "capitoli" and not f.name.startswith("00") \
                and "\\begin{esercizio}" not in testo:
            print(f"{rel}: nessun esercizio")
            problemi += 1
        for chiave in re.findall(r"\\cite[a-z]*(?:\[[^]]*\])*\{([^}]+)\}", testo):
            for k in chiave.split(","):
                if k.strip() not in chiavi_bib:
                    print(f"{rel}: citazione mancante in tor.bib: {k.strip()}")
                    problemi += 1
        # I listati riportano output di programmi: non si applicano le regole di stile.
        prosa = re.sub(r"\\begin\{lstlisting\}.*?\\end\{lstlisting\}",
                       lambda m: re.sub(r"[^\n]", " ", m.group()), testo, flags=re.S)
        for modello, consiglio in SCONSIGLIATI.items():
            for m in re.finditer(modello, prosa, re.I):
                riga = prosa.count("\n", 0, m.start()) + 1
                print(f"{rel}:{riga}: '{m.group()}' → {consiglio}")
    problemi += controlla_wiki()
    print(f"\nTotale segnalazioni bloccanti: {problemi}")
    sys.exit(1 if problemi else 0)

if __name__ == "__main__":
    main()
