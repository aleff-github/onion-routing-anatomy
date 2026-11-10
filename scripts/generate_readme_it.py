#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""README.it.md e' la parte italiana di README.md, resa autonoma.

La fonte e' una sola: il blocco fra <!-- it:inizio --> e <!-- it:fine --> di README.md.
Questo script lo copia in README.it.md con un'intestazione propria e i titoli promossi di
un livello, cosi' le due versioni non possono divergere.

    python3 scripts/generate_readme_it.py           rigenera README.it.md
    python3 scripts/generate_readme_it.py --check   esce con 1 se README.it.md non e' aggiornato
"""
import re
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
SORGENTE = RADICE / "README.md"
DESTINAZIONE = RADICE / "README.it.md"

INTESTAZIONE = """\
<!-- File generato da scripts/generate_readme_it.py a partire da README.md: non modificarlo a mano. -->
# Anatomia di Tor

<p align="center">
  <img src="assets/social-preview.png" alt="Anatomia di Tor: anteprima grafica del manuale tecnico sul protocollo Tor" width="860">
</p>

<p align="center"><strong>Il protocollo dell'anonimato, byte per byte</strong> · <em>Onion Routing Anatomy</em></p>

<p align="center">
  <a href="README.md#english">English</a> · <a href="#scaricare-il-libro">Libro</a> · <a href="labs/it/wiki/">Laboratori</a> · <a href="#aiuta-a-migliorare-il-libro">Contribuisci</a>
</p>

"""


def genera() -> str:
    testo = SORGENTE.read_text(encoding="utf-8")
    m = re.search(r"<!-- it:inizio[^>]*-->\n(.*?)<!-- it:fine -->", testo, re.S)
    if not m:
        sys.exit("README.md: marcatori <!-- it:inizio --> / <!-- it:fine --> non trovati")
    blocco = m.group(1)
    blocco = re.sub(r"\A## Italiano\n\n", "", blocco)
    blocco = re.sub(r"^### ", "## ", blocco, flags=re.M)
    return INTESTAZIONE + blocco


def main() -> int:
    atteso = genera()
    if "--check" in sys.argv[1:]:
        attuale = DESTINAZIONE.read_text(encoding="utf-8") if DESTINAZIONE.exists() else ""
        if attuale != atteso:
            print("README.it.md non corrisponde alla parte italiana di README.md: "
                  "esegui python3 scripts/generate_readme_it.py")
            return 1
        print("README.it.md: allineato a README.md")
        return 0
    DESTINAZIONE.write_text(atteso, encoding="utf-8")
    print(f"Scritto {DESTINAZIONE.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
