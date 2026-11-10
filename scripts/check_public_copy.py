#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prevents pre-publication and internal-workflow notices in reader-facing copy.

Technical documentation, release procedures, audit records and the actual status
of untranslated/unreviewed editions are intentionally outside this editorial gate.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANGUAGES = ("en", "it", "es", "ru", "zh-Hans")
BOOK_FILES = (
    "anatomia-di-tor_it_A4.pdf",
    "anatomia-di-tor_it.epub",
    "anatomia-di-tor_it_7x10.pdf",
)
PUBLIC_FILES = (
    "README.md",
    "README.it.md",
    "book/README.md",
    "labs/README.md",
    "CHANGELOG.md",
    "AI_DISCLOSURE.md",
    "docs/translation-review.md",
    *(f"docs/translations/{lang}.md" for lang in LANGUAGES if lang != "it"),
    *(f"website/i18n/{lang}.toml" for lang in LANGUAGES),
    # Compiled book sources in every language, excluding LaTeX-only commentary.
    *(p.relative_to(ROOT).as_posix()
      for p in sorted((ROOT / "source").glob("*/*.tex"))),
    *(p.relative_to(ROOT).as_posix()
      for p in sorted((ROOT / "source").glob("*/*/*.tex"))),
    # Reader-facing laboratory guides in Italian and all four translations.
    *(p.relative_to(ROOT).as_posix()
      for p in sorted((ROOT / "labs").glob("*/wiki/*.md"))),
    *(p.relative_to(ROOT).as_posix()
      for p in sorted((ROOT / "labs").glob("*/вики/*.md"))),
    *(p.relative_to(ROOT).as_posix()
      for p in sorted((ROOT / "labs").glob("*/维基/*.md"))),
)
# Keep these specific: generic words like 'review' are required in the honest
# disclosure of AI usage and lack of independent reviews.
FORBIDDEN = (
    "first edition in preparation",
    "prima edizione in preparazione",
    "the release is in preparation",
    "la release è in preparazione",
    "la release e in preparazione",
    "la release está en preparación",
    "la release está en prepar",
    "релиз готовится",
    "发布版正在准备中",
    "该发布版正在准备中",
    "these links lead to the edition files on the repository branch",
    "questi collegamenti puntano ai file sul ramo della repository",
    "the publication date will be recorded here",
    "no download yet",
    "nessun download per ora",
    "sin descarga por ahora",
    "скачать пока нельзя",
    "暂不提供下载",
    "not a finished product",
    "non è un prodotto finito",
    "no es un producto terminado",
    "не законченный продукт",
    "不是一件已经完成的产品",
)


def audit() -> list[str]:
    issues = []
    for name in PUBLIC_FILES:
        path = ROOT / name
        if not path.is_file():
            issues.append(f"{name}: file assente")
            continue
        content = path.read_text(encoding="utf-8")
        if path.suffix == ".tex":
            # LaTeX comments are source-maintainer notes, not printed text.
            content = re.sub(r"(?m)^\\s*%[^\\n]*$", "", content)
        content = content.casefold()
        for expression in FORBIDDEN:
            if expression.casefold() in content:
                issues.append(f"{name}: riferimento di lavorazione rivolto al lettore: {expression}")
    for lang in LANGUAGES:
        path = ROOT / "website/i18n" / f"{lang}.toml"
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (ValueError, KeyError) as exc:
            issues.append(f"{path.relative_to(ROOT)}: TOML non valido ({exc})")
            continue
        download = data["download"]
        for file in BOOK_FILES:
            if f"{{{{blob}}}}/book/it/{file}" not in download["pending"]:
                issues.append(f"website/i18n/{lang}.toml: manca il link diretto a {file}")
        footer = data["footer"]["edition"]
        if any(x in footer for x in ("{{commit}}", "{{commit_url}}", "{{tag}}")):
            issues.append(f"website/i18n/{lang}.toml: footer con dettagli di build")
        if not data["pages"]["languages"]["body"]:
            issues.append(f"website/i18n/{lang}.toml: pagina lingue assente")
    config = tomllib.loads((ROOT / "website/site.toml").read_text(encoding="utf-8"))
    pages_a4 = config["edition"]["pages_a4"]
    pages_print = config["edition"]["pages_7x10"]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for count in (f"PDF A4 ({pages_a4} pages)", f"({pages_print} pages)"):
        if count not in changelog:
            issues.append(f"CHANGELOG.md: pagine correnti non indicate ({count})")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for count in (f"{pages_a4} pages", f"{pages_print} pages",
                  f"{pages_a4} pagine", f"{pages_print} pagine"):
        if count not in readme:
            issues.append(f"README.md: conteggio pagine mancante: {count}")
    return issues


if __name__ == "__main__":
    errors = audit()
    for error in errors:
        print(error)
    print(f"Testi rivolti ai lettori: {len(PUBLIC_FILES)} file, {len(errors)} problemi")
    sys.exit(1 if errors else 0)
