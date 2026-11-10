#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Copia bozze di traduzione compilate in book/<lingua>/; non crea release."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Titoli e nomi dei file nella lingua corrispondente.
EDITIONS = {
    "en": ("anatomy-of-tor_en", "cover.png", "cover"),
    "es": ("anatomía-de-tor_es", "portada.png", "portada"),
    "ru": ("анатомия-tor_ru", "обложка.png", "обложка"),
    "zh-Hans": ("tor-解剖_zh-Hans", "封面.png", "封面"),
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in EDITIONS:
        print("Uso: python3 scripts/export_draft_book.py en|es|ru|zh-Hans", file=sys.stderr)
        return 2
    lang = sys.argv[1]
    stem, cover_file, cover_name = EDITIONS[lang]
    source = ROOT / "source" / lang
    dest = ROOT / "book" / lang
    copies = {
        "main.pdf": f"{stem}_A4.pdf",
        "epub.epub": f"{stem}.epub",
        cover_file: f"{stem}_{cover_name}.png",
    }
    missing = [name for name in copies if not (source / name).is_file() or (source / name).stat().st_size == 0]
    if missing:
        print(f"Bozza {lang}: mancano file compilati non vuoti: {', '.join(missing)}", file=sys.stderr)
        return 1
    dest.mkdir(parents=True, exist_ok=True)
    for src, name in copies.items():
        shutil.copy2(source / src, dest / name)
        print(f"Bozza non verificata: {dest.relative_to(ROOT) / name}")
    print("Questi file NON entrano in v1.0.0-it e NON attestano una revisione linguistica.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
