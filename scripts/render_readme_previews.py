#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Anteprime autentiche del PDF italiano per i README, non immagini ricostruite.

Esecuzione: python3 scripts/render_readme_previews.py
Verifica:   python3 scripts/render_readme_previews.py --check

Le pagine e l'impronta sono fissate: dopo modifiche al PDF occorre verificare
visivamente le anteprime e aggiornare i riferimenti, senza rigenerarle alla cieca.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PDF = ROOT / "book/it/anatomia-di-tor_it_A4.pdf"
OUT = ROOT / "assets/anteprime"
PDF_SHA256 = "cabfa92805a19192834713920473bda70ac7e75e490daf218769a0b7c3c8ec40"
PAGES = 298
WIDTH = 840
SAMPLES = (
    ("celle-formati.png", 63, "Formato delle celle Tor", "Tor cell wire format"),
    ("costruzione-circuito.png", 78, "Costruzione telescopica dei circuiti", "Telescopic circuit construction"),
    ("rendezvous-onion-service.png", 131, "Rendezvous degli onion service", "Onion service rendezvous"),
    ("rete-privata.png", 170, "Topologia della rete Tor privata", "Private Tor network topology"),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def png_dimensions(path):
    data = path.read_bytes()[:24]
    if len(data) != 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError(f"non è un PNG valido: {path}")
    return struct.unpack(">II", data[16:24])


def verify_source():
    if not PDF.is_file() or digest(PDF) != PDF_SHA256:
        raise ValueError("PDF diverso da quello esaminato: ricontrollare pagine e selezione anteprime")


def render():
    verify_source()
    info = subprocess.check_output(["pdfinfo", str(PDF)], text=True)
    actual = int(next(line.split(":", 1)[1] for line in info.splitlines() if line.startswith("Pages:")))
    if actual != PAGES:
        raise ValueError(f"pagine PDF inattese: {actual} invece di {PAGES}")
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for name, page, title_it, title_en in SAMPLES:
        prefix = OUT / name.removesuffix(".png")
        subprocess.run(["pdftoppm", "-f", str(page), "-l", str(page),
                        "-scale-to-x", str(WIDTH), "-scale-to-y", "-1",
                        "-png", "-singlefile", str(PDF), str(prefix)], check=True)
        target = OUT / name
        if png_dimensions(target)[0] != WIDTH:
            raise ValueError(f"larghezza inattesa: {target}")
        results.append({"file": name, "pdf_page": page, "title_it": title_it,
                        "title_en": title_en, "sha256": digest(target)})
    manifest = {"schema": 1, "source_pdf": PDF.relative_to(ROOT).as_posix(),
                "source_sha256": PDF_SHA256, "source_pages": PAGES,
                "width_px": WIDTH, "samples": results}
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    check()
    print("Anteprime italiane renderizzate da PDF verificato: 4/4")


def check():
    verify_source()
    manifest_path = OUT / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("manifest anteprime mancante")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {"schema": 1, "source_pdf": PDF.relative_to(ROOT).as_posix(),
                "source_sha256": PDF_SHA256, "source_pages": PAGES, "width_px": WIDTH}
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise ValueError("manifest incoerente con il PDF in repository")
    rows = manifest.get("samples")
    if not isinstance(rows, list) or len(rows) != len(SAMPLES):
        raise ValueError("numero di anteprime inatteso")
    for row, (name, page, title_it, title_en) in zip(rows, SAMPLES):
        png = OUT / name
        if any(row.get(k) != v for k, v in {"file": name, "pdf_page": page,
                "title_it": title_it, "title_en": title_en}.items()):
            raise ValueError(f"anteprima incoerente: {name}")
        if not png.is_file() or digest(png) != row.get("sha256"):
            raise ValueError(f"checksum non valido: {name}")
        width, height = png_dimensions(png)
        if width != WIDTH or not 1100 <= height <= 1250:
            raise ValueError(f"dimensioni anteprima incoerenti: {name}: {width}×{height}")
    print("Anteprime: PDF sorgente e 4/4 immagini coerenti")


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--check"]:
            check()
        elif not sys.argv[1:]:
            render()
        else:
            raise ValueError("uso: --check")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Anteprime NON verificate: {error}", file=sys.stderr)
        sys.exit(1)
