#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare and publish four translated GitHub Releases without GitHub Actions.

Default: preflight/dry run. Publish with --publish. Requires git, GitHub CLI
(gh) and an authenticated account with release permissions. Uses only files
already versioned under book/<language>/; it does not build new artefacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "aleff-github/onion-routing-anatomy"
# language code, localized release title, A4 PDF, EPUB 3, cover
EDITIONS = (
    ("en", "Anatomy of Tor 1.0.0 — English edition",
     "anatomy-of-tor_en_A4.pdf", "anatomy-of-tor_en.epub",
     "anatomy-of-tor_en_cover.png"),
    ("es", "Anatomía de Tor 1.0.0 — edición en español",
     "anatomía-de-tor_es_A4.pdf", "anatomía-de-tor_es.epub",
     "anatomía-de-tor_es_portada.png"),
    ("ru", "Анатомия Tor 1.0.0 — русское издание",
     "анатомия-tor_ru_A4.pdf", "анатомия-tor_ru.epub",
     "анатомия-tor_ru_обложка.png"),
    ("zh-Hans", "Tor 解剖 1.0.0 — 简体中文版",
     "tor-解剖_zh-Hans_A4.pdf", "tor-解剖_zh-Hans.epub",
     "tor-解剖_zh-Hans_封面.png"),
)


# GitHub Releases sanitizes non-ASCII asset names; use portable ASCII on release
# assets while preserving language-specific Unicode names in book/<language>/.
RELEASE_ASSET_NAMES = {
    "en": [
        "anatomy-of-tor_en_A4.pdf",
        "anatomy-of-tor_en.epub",
        "anatomy-of-tor_en_cover.png"
    ],
    "es": [
        "anatomia-de-tor_es_A4.pdf",
        "anatomia-de-tor_es.epub",
        "anatomia-de-tor_es_portada.png"
    ],
    "ru": [
        "anatomiya-tor_ru_A4.pdf",
        "anatomiya-tor_ru.epub",
        "anatomiya-tor_ru_oblozhka.png"
    ],
    "zh-Hans": [
        "tor-jiepou_zh-Hans_A4.pdf",
        "tor-jiepou_zh-Hans.epub",
        "tor-jiepou_zh-Hans_fengmian.png"
    ]
}


def command(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args, cwd=ROOT, text=True, encoding="utf-8",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"Comando non riuscito ({result.returncode}): {' '.join(args)}\n"
            + (result.stderr or result.stdout).strip()
        )
    return result


def preflight() -> tuple[str, set[str]]:
    for binary in ("git", "gh"):
        if shutil.which(binary) is None:
            raise RuntimeError(f"Comando mancante: {binary}")
    if Path(command("git", "rev-parse", "--show-toplevel").stdout.strip()).resolve() != ROOT:
        raise RuntimeError("Esegui lo script nel checkout corretto della repository.")
    remote = command("git", "remote", "get-url", "origin").stdout.strip()
    normalized = remote.removesuffix(".git")
    if normalized not in (
        "https://github.com/" + REPOSITORY,
        "git@github.com:" + REPOSITORY,
        "ssh://git@github.com/" + REPOSITORY,
    ):
        raise RuntimeError(f"Remote origin inatteso: {remote}")
    if command("git", "status", "--porcelain", "--untracked-files=no").stdout.strip():
        raise RuntimeError("Il checkout contiene modifiche tracciate: esegui commit o ripristino.")
    if command("git", "branch", "--show-current").stdout.strip() != "main":
        raise RuntimeError("Passa al branch main prima della pubblicazione.")
    command("gh", "auth", "status")
    command("git", "fetch", "--quiet", "origin", "main")
    head = command("git", "rev-parse", "HEAD").stdout.strip()
    tracked = command("git", "rev-parse", "origin/main").stdout.strip()
    if head != tracked:
        raise RuntimeError("Checkout non aggiornato: esegui git pull --ff-only e riprova.")
    command("gh", "repo", "view", REPOSITORY, "--json", "nameWithOwner")
    output = command(
        "gh", "release", "list", "--repo", REPOSITORY, "--json", "tagName",
        "--limit", "100",
    ).stdout
    releases = {row["tagName"] for row in json.loads(output)}
    for lang, _title, pdf, epub, cover in EDITIONS:
        tag = f"v1.0.0-{lang}"
        for file in (
            ROOT / "book" / lang / pdf,
            ROOT / "book" / lang / epub,
            ROOT / "book" / lang / cover,
            ROOT / "docs" / "releases" / f"{tag}.md",
            ROOT / "LICENSE",
            ROOT / "NOTICE.md",
        ):
            if not file.is_file() or file.stat().st_size == 0:
                raise RuntimeError(f"File mancante o vuoto: {file.relative_to(ROOT)}")
        if tag not in releases:
            # Refuse to re-use an orphan tag; never move existing tags.
            existing = command(
                "git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"
            ).stdout.strip()
            if existing:
                raise RuntimeError(
                    f"Il tag {tag} esiste già senza una release rilevata: verifica prima."
                )
    return head, releases


def stage_files(folder: Path, edition: tuple[str, ...]) -> list[Path]:
    lang, _title, pdf, epub, cover = edition
    tag = f"v1.0.0-{lang}"
    sources = (
        ROOT / "book" / lang / pdf,
        ROOT / "book" / lang / epub,
        ROOT / "book" / lang / cover,
    )
    for source, basename in zip(sources, RELEASE_ASSET_NAMES[lang], strict=True):
        shutil.copy2(source, folder / basename)
    for path in (ROOT / "LICENSE", ROOT / "NOTICE.md"):
        shutil.copy2(path, folder / path.name)
    shutil.copy2(
        ROOT / "docs" / "releases" / f"{tag}.md", folder / "RELEASE-NOTES.md"
    )
    assets = sorted(folder.iterdir(), key=lambda x: x.name)
    lines = [
        hashlib.sha256(file.read_bytes()).hexdigest() + "  " + file.name
        for file in assets
    ]
    checksums = folder / "SHA256SUMS"
    checksums.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [*assets, checksums]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--publish", action="store_true",
        help="Crea le release GitHub e carica gli allegati (default: sola verifica).",
    )
    args = parser.parse_args()
    head, already_published = preflight()
    print(f"Repository: {REPOSITORY}\nCommit sorgente: {head}")
    for edition in EDITIONS:
        lang, title, *_ = edition
        tag = f"v1.0.0-{lang}"
        if tag in already_published:
            print(f"{tag}: già esistente, nessuna modifica")
            continue
        with tempfile.TemporaryDirectory(prefix="onion-release-") as folder:
            assets = stage_files(Path(folder), edition)
            print(f"{tag}: {len(assets)} file controllati; SHA-256 generati")
            if not args.publish:
                continue
            # gh creates the tag at the exact checked commit when absent.
            # --latest=false preserves the Italian release as Latest.
            command(
                "gh", "release", "create", tag,
                "--repo", REPOSITORY, "--target", head, "--latest=false",
                "--title", title,
                "--notes-file", str(ROOT / "docs" / "releases" / f"{tag}.md"),
                *[str(p) for p in assets],
            )
            info = json.loads(command(
                "gh", "release", "view", tag, "--repo", REPOSITORY,
                "--json", "url,tagName,isDraft",
            ).stdout)
            if info["isDraft"]:
                raise RuntimeError(f"Release rimasta in bozza: {info['url']}")
            print(f"{tag}: PUBBLICATA — {info['url']}")
    if not args.publish:
        print("\nNessuna release creata. Pubblica con: "
              "python3 scripts/publish_translated_releases.py --publish")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(f"ERRORE: {error}", file=sys.stderr)
        sys.exit(1)
