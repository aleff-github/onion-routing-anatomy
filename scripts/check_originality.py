#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controllo di originalità: cerca sequenze di N parole identiche tra il testo
del libro e un corpus di riferimento (specifiche, articoli, altri libri).

Uso: python3 scripts/check_originality.py [--n 8] [cartella_corpus ...]
Corpus predefinito: fonti/ (torspec e, in fonti/confronto/, qualsiasi testo
.txt/.md/.tex che si vogliano confrontare, per esempio testi italiani su Tor).

Limite: rileva le copie letterali e le parafrasi molto strette nella stessa lingua,
non le traduzioni. Per quelle valgono le regole di docs/it/redazione/originalita.md.
"""
import argparse
import re
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
ESTENSIONI = {".md", ".txt", ".tex"}
# Sequenze che devono restare letterali: denominazioni e citazioni di norme, che vanno
# riportate con le parole esatte del legislatore. Elenco e motivi in docs/it/redazione/originalita.md.
AMMESSE = RADICE / "scripts" / "data" / "literal-quotations.txt"


def ammesse() -> set[str]:
    if not AMMESSE.is_file():
        return set()
    return {r.split("#")[0].strip() for r in AMMESSE.read_text().splitlines()
            if r.split("#")[0].strip()}


def solo_numeri(g: str) -> bool:
    """Una sequenza fatta in maggioranza di numeri non è prosa: sono indirizzi, porte,
    articoli di legge. Coincide per forza con la fonte, e non dice nulla sul plagio."""
    tok = g.split()
    return sum(t.isdigit() for t in tok) * 2 >= len(tok)


def parole(testo: str) -> list[str]:
    testo = re.sub(r"%.*", " ", testo)                      # commenti LaTeX
    # Listati (output di programmi, codice) e URL non sono prosa: si escludono.
    testo = re.sub(r"\\begin\{lstlisting\}.*?\\end\{lstlisting\}", " ", testo, flags=re.S)
    testo = re.sub(r"\\url\{[^}]*\}", " ", testo)
    # Formule matematiche (fatti, non prosa) e titoli di opere citate.
    testo = re.sub(r"\\\[.*?\\\]|\$[^$]*\$", " ", testo, flags=re.S)
    testo = re.sub(r"\\emph\{[^}]*\}~?\\cite", " ", testo)
    testo = re.sub(r"\\titolo\{[^}]*\}", " ", testo)
    testo = re.sub(r"\\spec\{[^}]*\}\{[^}]*\}", " ", testo)   # nomi di sezioni citate
    testo = re.sub(r"\\[a-zA-Z]+\*?(\[[^]]*\])?", " ", testo)  # comandi LaTeX
    return re.findall(r"[a-zàèéìòù0-9_']+", testo.lower())


def ngrammi(p: list[str], n: int):
    return (" ".join(p[i:i + n]) for i in range(len(p) - n + 1))


def costruisci_indice(corpora: list[str], n: int) -> dict[str, str]:
    """Indicizza solo fonti reali: un corpus mancante o vuoto non equivale a nessuna coincidenza."""
    if n < 2:
        raise ValueError("il numero di parole per sequenza deve essere almeno 2")
    indice: dict[str, str] = {}
    file_utili = 0
    for c in corpora:
        percorso = Path(c)
        if not percorso.exists():
            raise ValueError(f"corpus non trovato: {percorso}")
        candidati = [percorso] if percorso.is_file() else percorso.rglob("*")
        for f in candidati:
            if f.is_file() and f.suffix.lower() in ESTENSIONI:
                tokens = parole(f.read_text(errors="ignore"))
                if len(tokens) < n:
                    continue
                file_utili += 1
                for g in ngrammi(tokens, n):
                    indice.setdefault(g, str(f))
    if file_utili == 0:
        raise ValueError("nessun file di riferimento con testo sufficiente: "
                         "popolare fonti/ oppure indicare un corpus esplicito")
    return indice


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("corpus", nargs="*", default=[str(RADICE / "fonti")])
    a = ap.parse_args()

    try:
        indice = costruisci_indice(a.corpus, a.n)
    except ValueError as errore:
        print(f"Controllo originalità NON ESEGUITO: {errore}", file=sys.stderr)
        sys.exit(2)

    consentite, trovati, saltate = ammesse(), 0, 0
    for f in sorted(p for p in (RADICE / "source" / "it").glob("*/*.tex") if p.parent.name != "figure"):
        visti = set()
        for g in ngrammi(parole(f.read_text()), a.n):
            if g not in indice or g in visti:
                continue
            visti.add(g)
            if solo_numeri(g) or any(g in c for c in consentite):
                saltate += 1
                continue
            trovati += 1
            print(f"{f.relative_to(RADICE)}: «{g}» ← {indice[g]}")
    if saltate:
        print(f"({saltate} sequenze ammesse: numeri, o citazioni letterali di norme "
              f"elencate in scripts/data/literal-quotations.txt)")
    print(f"\nSequenze di {a.n} parole in comune con il corpus: {trovati}")
    sys.exit(1 if trovati else 0)


if __name__ == "__main__":
    main()
