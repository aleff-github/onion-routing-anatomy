#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controlli prima di pubblicare una release (docs/maintainers/release-procedure.md). Non crea tag ne'
release: verifica soltanto che tutto sia coerente.

- la versione coincide fra Makefile, website/site.toml, CHANGELOG.md e note di rilascio;
- le impronte abbreviate nelle note corrispondono ai file di book/<lingua>/;
- il pacchetto di make release-package esiste, i suoi SHA256SUMS sono corretti e contiene
  gli stessi file di book/ e le stesse note;
- l'albero di lavoro e' pulito e, se il tag esiste gia', punta al commit corrente o a un
  commit precedente con gli stessi file del libro e le stesse note.

    python3 scripts/check_release.py
"""
import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent


def sha256(percorso):
    return hashlib.sha256(percorso.read_bytes()).hexdigest()


def main():
    problemi = []
    makefile = (RADICE / "Makefile").read_text(encoding="utf-8")
    versione = re.search(r"^VERSIONE \?= (\S+)", makefile, re.M).group(1)
    lingua = re.search(r"^LINGUA\s+\?= (\S+)", makefile, re.M).group(1)
    conf = tomllib.loads((RADICE / "website" / "site.toml").read_text(encoding="utf-8"))
    tag = f"v{versione}-{lingua}"
    if conf["edition"]["version"] != versione or conf["release"]["tag"] != tag:
        problemi.append(f"website/site.toml non corrisponde a {tag}")
    changelog = (RADICE / "CHANGELOG.md").read_text(encoding="utf-8")
    # Una sezione per versione, comune a tutte le lingue; il tag della lingua va citato.
    if not re.search(rf"^## {re.escape(versione)}\b", changelog, re.M):
        problemi.append(f"CHANGELOG.md: manca la sezione {versione}")
    elif tag not in changelog:
        problemi.append(f"CHANGELOG.md: la sezione {versione} non cita la release {tag}")
    note = RADICE / "docs" / "releases" / f"{tag}.md"
    if not note.exists():
        problemi.append(f"mancano le note {note.relative_to(RADICE)}")
        testo_note = ""
    else:
        testo_note = note.read_text(encoding="utf-8")

    libro = RADICE / "book" / lingua
    rel = conf["release"]
    attesi = [rel["pdf"], rel["epub"], rel["print"], f"anatomia-di-tor_{lingua}_copertina.png"]
    impronte = {}
    for nome in attesi:
        f = libro / nome
        if not f.exists():
            problemi.append(f"manca book/{lingua}/{nome}")
            continue
        impronte[nome] = sha256(f)
        h = impronte[nome]
        if nome not in testo_note:
            problemi.append(f"le note non citano {nome}")
        elif f"{h[:8]}…{h[-7:]}" not in testo_note:
            problemi.append(f"le note riportano un'impronta diversa per {nome}")

    pacchetto = RADICE / "dist" / f"onion-routing-anatomy-{tag}"
    if not pacchetto.is_dir():
        problemi.append(f"manca il pacchetto {pacchetto.relative_to(RADICE)} (make release-package)")
    else:
        somme = {}
        for riga in (pacchetto / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            h, nome = riga.split(maxsplit=1)
            somme[nome] = h
            file_pacchetto = pacchetto / nome
            if not file_pacchetto.is_file():
                problemi.append(f"SHA256SUMS: file mancante nel pacchetto: {nome}")
            elif sha256(file_pacchetto) != h:
                problemi.append(f"SHA256SUMS: impronta errata per {nome}")
        for nome, h in impronte.items():
            if somme.get(nome) != h:
                problemi.append(f"il pacchetto contiene un {nome} diverso da book/{lingua}/")
        if note.exists() and (pacchetto / "RELEASE-NOTES.md").read_bytes() != note.read_bytes():
            problemi.append("RELEASE-NOTES.md del pacchetto diverso dalle note attuali")
        # Anche le attribuzioni di terzi devono accompagnare i file distribuiti.
        for nome in ("LICENSE", "NOTICE.md"):
            copia = pacchetto / nome
            impronta = sha256(RADICE / nome)
            if not copia.is_file():
                problemi.append(f"{nome} mancante nel pacchetto")
            elif sha256(copia) != impronta:
                problemi.append(f"{nome} del pacchetto diverso da quello della repository")
            if somme.get(nome) != impronta:
                problemi.append(f"SHA256SUMS: impronta mancante o errata per {nome}")
        archivio = RADICE / "dist" / f"onion-routing-anatomy-{tag}.zip"
        firma = archivio.with_name(archivio.name + ".sha256")
        if not archivio.exists() or not firma.exists() \
                or firma.read_text().split()[0] != sha256(archivio):
            problemi.append("ZIP del pacchetto assente o con impronta errata")

    def git(*a):
        return subprocess.run(["git", *a], cwd=RADICE, capture_output=True, text=True)
    if git("status", "--porcelain").stdout.strip():
        problemi.append("albero di lavoro con modifiche non registrate")
    testa = git("rev-parse", "HEAD").stdout.strip()
    tag_commit = git("rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}").stdout.strip()
    stato_tag = "non ancora creato"
    if tag_commit == testa:
        stato_tag = "punta al commit corrente"
    elif tag_commit:
        # Dopo il rilascio main va avanti (sito, README, changelog): va bene finche' i file
        # del libro e le note sono gli stessi del commit del tag.
        invariati = git("diff", "--quiet", tag_commit, testa, "--",
                        f"book/{lingua}", f"docs/releases/{tag}.md").returncode == 0
        if invariati:
            stato_tag = "su un commit precedente, con book/ e note invariati"
        else:
            stato_tag = "PUNTA A UN COMMIT CON FILE DIVERSI"
            problemi.append(f"book/{lingua} o le note sono cambiati dopo il tag {tag}")

    for p in problemi:
        print(p)
    print(f"Release {tag}: {len(impronte)} file, tag {stato_tag}, "
          f"sito {'pubblicata' if rel['published'] else 'in preparazione'}: {len(problemi)} problemi")
    return 1 if problemi else 0


if __name__ == "__main__":
    sys.exit(main())
