#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controlla che i riferimenti del libro alle fonti primarie esistano davvero.

Verifica tre cose, contro i sorgenti in fonti/ (torspec, tor, arti):
  1. ogni \\spec{documento}{sezione} punta a un documento di torspec e a una sua sezione;
  2. ogni \\proposta{NNN} corrisponde a una proposta esistente, e ne stampa il titolo;
  3. ogni nome di file o di funzione del codice di tor citato nel testo esiste.

Uso: python3 scripts/verify_spec_references.py [-v]
Le fonti non sono versionate: se mancano, il controllo corrispondente viene saltato
e segnalato come INCOMPLETO (codice di uscita 2), mai dato per superato.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
FONTI = RADICE / "fonti"
TORSPEC = FONTI / "torspec" / "spec"
PROPOSTE = FONTI / "torspec" / "proposals"
TOR = FONTI / "tor"
TESTI = sorted((RADICE / "source" / "it" / "capitoli").glob("*.tex")) + \
        sorted((RADICE / "source" / "it" / "appendici").glob("*.tex"))
WIKI = sorted((RADICE / "labs" / "it" / "wiki").glob("*.md"))

# Segnaposto usati negli esempi della guida di stile e dell'appendice C.
SEGNAPOSTO = {("documento", "sezione")}

problemi: list[str] = []
saltati: list[str] = []


def dissimula(s: str) -> str:
    """Toglie gli escape LaTeX da un frammento di testo."""
    return s.replace("\\_", "_").replace("\\&", "&").replace("\\%", "%").replace("\\#", "#")


def testo_di(documento: str) -> str | None:
    """Tutto il testo di un documento di torspec (file singolo o cartella)."""
    f = TORSPEC / f"{documento}.md"
    if f.is_file():
        return f.read_text(errors="replace")
    d = TORSPEC / documento
    if d.is_dir():
        return "\n".join(p.read_text(errors="replace") for p in sorted(d.rglob("*.md")))
    return None


def titoli(testo: str) -> set[str]:
    """I titoli di sezione di un documento markdown, normalizzati.

    Di un titolo come «`pr` --- Subprotocol capabilities supported» si indicizzano sia
    il titolo intero sia il nome dell'item che lo apre: torspec usa entrambe le forme."""
    fuori = set()
    for riga in testo.splitlines():
        if not riga.startswith("#"):
            continue
        titolo = riga.lstrip("#").strip()
        fuori.add(normalizza(titolo))
        for sep in ("---", "\u2014", "--"):
            if sep in titolo:
                fuori.add(normalizza(titolo.split(sep)[0]))
                break
    return fuori


def normalizza(s: str) -> str:
    s = re.sub(r"\{\s*#.*?\}", "", s)            # ancore { #id } di mdbook
    s = re.sub(r"\\?\[[A-Z0-9_]+\\?\]", "", s)      # etichette \[ONIONADDRESS\]
    s = re.sub(r"[`*_\\]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower().rstrip(".")


def controlla_spec() -> None:
    if not TORSPEC.is_dir():
        saltati.append("torspec assente: riferimenti \\spec non verificati")
        return
    visti = set()
    for f in TESTI:
        for doc, sez in re.findall(r"\\spec\{([^}]*)\}\{([^}]*)\}", f.read_text()):
            doc, sez = dissimula(doc), dissimula(sez)
            if (doc, sez) in SEGNAPOSTO or (doc, sez) in visti:
                continue
            visti.add((doc, sez))
            testo = testo_di(doc)
            if testo is None:
                problemi.append(f"{f.name}: \\spec: documento inesistente in torspec: {doc}")
                continue
            if normalizza(sez) not in titoli(testo):
                problemi.append(f"{f.name}: \\spec{{{doc}}}: sezione non trovata: «{sez}»")
    print(f"  \\spec: {len(visti)} riferimenti distinti controllati")


def controlla_proposte(verboso: bool) -> None:
    if not PROPOSTE.is_dir():
        saltati.append("proposte assenti: riferimenti \\proposta non verificati")
        return
    per_numero = {}
    for p in list(PROPOSTE.glob("*.txt")) + list(PROPOSTE.glob("*.md")):
        m = re.match(r"(\d{3})-", p.name)
        if m:
            per_numero[int(m.group(1))] = p
    visti = {}
    for f in TESTI:
        for n in re.findall(r"\\proposta\{(\d+)\}", f.read_text()):
            n = int(n)
            if n in visti:
                continue
            p = per_numero.get(n)
            if p is None:
                problemi.append(f"{f.name}: \\proposta{{{n}}}: nessuna proposta con questo numero")
                continue
            titolo = ""
            for riga in p.read_text(errors="replace").splitlines()[:12]:
                if riga.lower().startswith("title:"):
                    titolo = riga.split(":", 1)[1].strip()
                    break
            visti[n] = titolo
    print(f"  \\proposta: {len(visti)} proposte distinte, tutte esistenti")
    if verboso:
        for n in sorted(visti):
            print(f"      {n}: {visti[n]}")


def controlla_codice() -> None:
    """I percorsi e gli identificatori citati nel testo devono esistere da qualche parte:
    nei sorgenti di tor o di Arti, oppure nel codice del libro. Un identificatore che non
    si trova in nessuno dei tre è quasi sempre un refuso o un ricordo sbagliato."""
    if not TOR.is_dir():
        saltati.append("sorgenti di tor assenti: riferimenti al codice non verificati")
        return
    corpus = []
    for base, suffissi in ((TOR, (".c", ".h")), (FONTI / "arti", (".rs", ".toml")),
                           (RADICE / "labs" / "it" / "codice", (".py",)), (RADICE / "labs" / "it" / "laboratorio", (".py",))):
        if base.is_dir():
            corpus += [p.read_text(errors="replace") for p in base.rglob("*")
                       if p.suffix in suffissi]
    nomi = {p.name for p in TOR.rglob("*")} | {p.name for p in (RADICE / "labs" / "it" / "codice").rglob("*")}
    testo_corpus = "\n".join(corpus)
    # API di terze parti usate nel libro e assenti, per costruzione, da questi sorgenti.
    ESTERNE = {"recover_data_from_signature",      # cryptography
               "create_ephemeral_hidden_service", "get_network_status",  # stem
               "hs_ed25519_public_key", "hs_ed25519_secret_key"}         # file di tor, non simboli
    file_visti, id_visti = set(), set()
    for f in TESTI:
        contenuto = f.read_text()
        for percorso in re.findall(r"src/[\w/\\.-]+\.[ch]\b", contenuto):
            percorso = dissimula(percorso).rstrip(".")
            if percorso in file_visti:
                continue
            file_visti.add(percorso)
            if not (TOR / percorso).is_file():
                problemi.append(f"{f.name}: file inesistente nei sorgenti di tor: {percorso}")
        for m in re.findall(r"\\(?:file|texttt|cmd)\{([^}]*)\}", contenuto):
            nome = dissimula(m)
            if not re.fullmatch(r"[a-z][a-z0-9_]*", nome) or nome.count("_") < 2:
                continue
            if nome in id_visti or nome in ESTERNE:
                continue
            id_visti.add(nome)
            if nome not in nomi and not re.search(rf"\b{re.escape(nome)}\b", testo_corpus):
                problemi.append(f"{f.name}: identificatore non trovato in nessun sorgente: {nome}")
    print(f"  codice: {len(file_visti)} percorsi e {len(id_visti)} identificatori controllati")


def controlla_spec_wiki() -> None:
    """Le pagine della wiki citano le sezioni di torspec in forma «doc, *Sezione*»:
    anche quelle devono esistere, altrimenti la wiki invecchia senza accorgersene."""
    if not TORSPEC.is_dir() or not WIKI:
        return
    documenti = {p.stem for p in TORSPEC.glob("*.md")} | {p.name for p in TORSPEC.iterdir() if p.is_dir()}
    visti = set()
    for f in WIKI:
        for doc, sez in re.findall(r"\b([a-z0-9-]+-spec), \*([^*]+)\*", f.read_text()):
            if doc not in documenti or (doc, sez) in visti:
                continue
            visti.add((doc, sez))
            testo = testo_di(doc)
            if testo is None or normalizza(sez) not in titoli(testo):
                problemi.append(f"labs/it/wiki/{f.name}: sezione non trovata in {doc}: «{sez}»")
    print(f"  wiki: {len(visti)} riferimenti a torspec controllati")


def main() -> None:
    verboso = "-v" in sys.argv
    print("Verifica dei riferimenti alle fonti primarie:")
    controlla_spec()
    controlla_spec_wiki()
    controlla_proposte(verboso)
    controlla_codice()
    for s in saltati:
        print(f"  [--] {s}")
    if problemi:
        print(f"\n{len(problemi)} riferimenti da correggere:")
        for p in problemi:
            print(f"  {p}")
    elif saltati:
        print("\nVerifica INCOMPLETA: mancano una o più fonti primarie.")
    else:
        print("\nNessun riferimento errato; tutte le fonti richieste sono disponibili.")
    # 1 = riferimenti errati, 2 = fonti incomplete, 0 = verifica effettivamente superata.
    sys.exit(1 if problemi else 2 if saltati else 0)


if __name__ == "__main__":
    main()
