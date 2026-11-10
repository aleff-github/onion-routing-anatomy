#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""I collegamenti relativi nei file Markdown della repository portano a file esistenti, e le
ancore (#sezione) a titoli esistenti, calcolati come fa GitHub. Controlla anche i link alla
repository stessa (blob/tree/modelli di issue). Le guide dei laboratori hanno il loro
controllo in check\_sources.py; i sorgenti delle traduzioni non sono Markdown pubblicato."""
import re
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
REPO = "https://github.com/aleff-github/onion-routing-anatomy"
ESCLUSI = ("labs/", "source/", "build/", "dist/", "fonti/")


def ancora(titolo):
    """Slug di GitHub: minuscole, via la punteggiatura, spazi -> trattini."""
    t = re.sub(r"<[^>]+>|`", "", titolo).strip().lower()
    t = re.sub(r"[^\w\- ]", "", t)
    return t.replace(" ", "-")


def ancore_di(percorso, cache={}):
    if percorso not in cache:
        testo = percorso.read_text(encoding="utf-8")
        testo = re.sub(r"```.*?```", "", testo, flags=re.S)
        visti, risultato = {}, set()
        for titolo in re.findall(r"^#{1,6}\s+(.+?)\s*#*$", testo, re.M):
            base = ancora(titolo)
            n = visti.get(base, 0)
            risultato.add(base if n == 0 else f"{base}-{n}")
            visti[base] = n + 1
        risultato |= set(re.findall(r'id="([^"]+)"', testo))
        cache[percorso] = risultato
    return cache[percorso]


def main():
    problemi = 0
    file_md = [p for p in RADICE.rglob("*.md")
               if not p.relative_to(RADICE).as_posix().startswith(ESCLUSI)]
    for f in sorted(file_md):
        rel = f.relative_to(RADICE)
        testo = re.sub(r"```.*?```", "", f.read_text(encoding="utf-8"), flags=re.S)
        destinazioni = re.findall(r"\]\(([^)\s]+)\)", testo) + re.findall(r'href="([^"]+)"', testo) \
            + re.findall(r'src="([^"]+)"', testo)
        for dest in destinazioni:
            if dest.startswith(REPO):
                resto = dest[len(REPO):]
                m = re.match(r"/(?:blob|tree)/main/([^#?]+)", resto)
                if m and not (RADICE / m.group(1)).exists():
                    print(f"{rel}: {dest} -> file assente")
                    problemi += 1
                m = re.match(r"/issues/new\?template=([^&#]+)", resto)
                if m and not (RADICE / ".github/ISSUE_TEMPLATE" / m.group(1)).exists():
                    print(f"{rel}: {dest} -> modello di issue assente")
                    problemi += 1
                continue
            if re.match(r"[a-z]+:", dest):
                continue
            percorso, _, frammento = dest.partition("#")
            bersaglio = (f.parent / percorso).resolve() if percorso else f
            if not bersaglio.exists():
                print(f"{rel}: {dest} -> file assente")
                problemi += 1
                continue
            if frammento and bersaglio.suffix == ".md" and frammento not in ancore_di(bersaglio):
                print(f"{rel}: {dest} -> ancora assente")
                problemi += 1
    print(f"Link Markdown: {len(file_md)} file, {problemi} problemi")
    return 1 if problemi else 0


if __name__ == "__main__":
    sys.exit(main())
