#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controlla che il codice del libro arrivi intatto sulla pagina stampata.

Estrae il testo da source/<lingua>/main.pdf e verifica che ogni riga di listato e ogni
frammento di codice inline compaia davvero nel PDF. Serve a scoprire i guasti
*silenziosi* della composizione: caratteri che LaTeX trasforma senza segnalare
nulla, e che nessun avviso del compilatore mostra.

Ne abbiamo trovati così:
  - listings stampava gli spazi dentro le stringhe come «␣» (showstringspaces,
    attivo per impostazione predefinita): il codice non era più copiabile;
  - in un nodo TikZ in carattere senza grazie le virgolette dritte di una stringa
    letterale diventavano tipografiche, per via della legatura +tlig del font;
  - nelle traduzioni, i caratteri oltre U+00FF (cirillico, cinese) uscivano fuori posto
    nei listati e perdevano gli spazi (source/shared/lst-unicode.lua);
  - nell'edizione russa «-» e «*» dei listati diventavano «−» e «∗» matematici.

Uso: python3 scripts/check_pdf_code.py [lingua...]     (predefinito: it)
Richiede `pdftotext` (poppler-utils); se manca, usa Docker.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
# Cartelle dei capitoli e delle appendici di ciascuna edizione.
CARTELLE = {"it": ("capitoli", "appendici"), "en": ("chapters", "appendices"),
            "es": ("capitulos", "apendices"), "ru": ("главы", "приложения"),
            "zh-Hans": ("章节", "附录")}

LEGATURE = {"\ufb00": "ff", "\ufb01": "fi", "\ufb02": "fl", "\ufb03": "ffi", "\ufb04": "ffl"}
# Sostituzioni LaTeX -> carattere, per confrontare il sorgente con la pagina.
SOSTITUZIONI = {r"\_": "_", r"\&": "&", r"\%": "%", r"\#": "#", r"\$": "$",
                r"\{": "{", r"\}": "}", r"\textbackslash ": "\\",
                r"\textbackslash": "\\", r"\ldots": "…", r"\allowbreak ": "", r"\allowbreak": ""}


def testi(lingua: str) -> list[Path]:
    base = RADICE / "source" / lingua
    return [f for cartella in CARTELLE[lingua] for f in sorted((base / cartella).rglob("*.tex"))]


def estrai(lingua: str) -> str:
    pdf = RADICE / "source" / lingua / "main.pdf"
    if not pdf.is_file():
        sys.exit(f"source/{lingua}/main.pdf non esiste: compila prima il PDF.")
    fuori = pdf.with_suffix(".txt")
    if shutil.which("pdftotext"):
        subprocess.run(["pdftotext", "-layout", str(pdf), str(fuori)], check=True)
    else:
        subprocess.run(
            ["docker", "run", "--rm", "-v", f"{RADICE}:/w", "debian:trixie-slim", "sh", "-c",
             "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq poppler-utils "
             f">/dev/null 2>&1 && pdftotext -layout /w/source/{lingua}/main.pdf "
             f"/w/source/{lingua}/main.txt"],
            check=True, capture_output=True)
    testo = fuori.read_text(encoding="utf-8", errors="replace")
    for k, v in LEGATURE.items():
        testo = testo.replace(k, v)
    # Testatina e numero di pagina, subito prima o subito dopo il cambio di pagina: un
    # percorso spezzato fra due pagine ("src/core/or/" | "extendinfo.c") altrimenti
    # risulterebbe interrotto da "267" o da "14.5. ДЕСКРИПТОР   119". Nella testatina
    # numero e titolo sono separati da molti spazi; nei listati il numero di riga da tre.
    testo = re.sub(r"\f[ \t]*(\d+|\d+ {8,}\S[^\n]*|\S[^\n]* {8,}\d+)[ \t]*\n", "\f\n", testo)
    return re.sub(r"\n[ \t]*\d+[ \t]*\n(\s*)\f", r"\n\1\f", testo)


def frammenti_inline(lingua: str) -> dict[str, str]:
    fuori = {}
    for f in testi(lingua):
        for m in re.findall(r"\\(?:file|texttt|opt|cmd)\{([^{}]*)\}", f.read_text()):
            s = m
            for k, v in SOSTITUZIONI.items():
                s = s.replace(k, v)
            if "\\" in s or "~" in m or len(s) < 4:
                continue                       # comandi residui: non confrontabili
            fuori.setdefault(s, f.name)
    return fuori


def righe_listato(lingua: str) -> list[tuple[str, str]]:
    fuori = []
    for f in testi(lingua):
        for m in re.finditer(r"\\begin\{lstlisting\}(?:\[[^\]]*\])?\n(.*?)\\end\{lstlisting\}",
                             f.read_text(), re.S):
            for riga in m.group(1).splitlines():
                r = riga.strip()
                if len(r) >= 25:
                    fuori.append((f.name, r))
    return fuori


def controlla(lingua: str) -> int:
    pdf = estrai(lingua)
    # Il confronto ignora gli spazi: listings manda a capo le righe lunghe, e va bene.
    compatto = re.sub(r"\s+", "", pdf)
    problemi = 0

    strani = {}
    for ch in set(pdf):
        if ch in "\n\t\f" or ch == " ":
            continue
        if unicodedata.category(ch).startswith("C") or ch in "\ufffd\u2423":
            strani[ch] = pdf.count(ch)
    if strani:
        problemi += len(strani)
        for ch, n in strani.items():
            nome = "spazio visibile" if ch == "\u2423" else unicodedata.name(ch, "?")
            print(f"carattere anomalo nel PDF: U+{ord(ch):04X} ({nome}) x{n}")

    def presente(s: str) -> str | None:
        """Cerca il frammento; se lo trova solo con le virgolette tipografiche,
        vuol dire che il font le ha sostituite in un contesto di codice."""
        senza = re.sub(r"\s+", "", s)
        if senza in compatto or senza.replace("\u2026", "...") in compatto:
            return None
        curve = senza.replace('"', "\u201d").replace("'", "\u2019")
        if curve in compatto or senza.replace('"', "\u201c") in compatto:
            return "virgolette tipografiche al posto di quelle dritte"
        return "assente"

    for s, f in frammenti_inline(lingua).items():
        esito = presente(s)
        if esito:
            problemi += 1
            print(f"{f}: codice inline «{s[:70]}» → {esito}")

    for f, r in righe_listato(lingua):
        esito = presente(r)
        if esito:
            problemi += 1
            print(f"{f}: riga di listato «{r[:70]}» → {esito}")

    print(f"{lingua}: {'nessun problema di composizione del codice' if not problemi else f'{problemi} problemi'}")
    return problemi


def main() -> None:
    lingue = sys.argv[1:] or ["it"]
    for lingua in lingue:
        if lingua not in CARTELLE:
            sys.exit(f"lingua sconosciuta: {lingua} (attese: {', '.join(CARTELLE)})")
    problemi = sum(controlla(lingua) for lingua in lingue)
    sys.exit(1 if problemi else 0)


if __name__ == "__main__":
    main()
