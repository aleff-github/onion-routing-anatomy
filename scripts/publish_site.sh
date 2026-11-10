#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
#
# Prepara il branch gh-pages con il sito generato da scripts/build_site.py, senza GitHub Actions.
#
#   scripts/publish_site.sh          genera, controlla e registra un commit sul branch
#                                     locale gh-pages (nessun invio a GitHub)
#   scripts/publish_site.sh --push   come sopra, poi invia gh-pages a origin
#
# Il commit di gh-pages riporta il commit sorgente e l'edizione del libro, cosi' ogni
# versione del sito si ricollega ai sorgenti da cui e' stata generata. Procedura completa
# e attivazione di GitHub Pages: docs/maintainers/github-pages.md.
set -eu

radice=$(git rev-parse --show-toplevel)
cd "$radice"

if [ -n "$(git status --porcelain)" ]; then
    echo "Ci sono modifiche non registrate: il sito non corrisponderebbe a un commit." >&2
    exit 1
fi

python3 scripts/build_site.py build
python3 scripts/build_site.py check

sorgente=$(git rev-parse HEAD)
edizione=$(python3 -c 'import tomllib; c = tomllib.load(open("website/site.toml", "rb")); print(c["edition"]["version"], c["release"]["tag"], "pubblicata" if c["release"]["published"] else "in preparazione")')

lavoro=$(mktemp -d)
trap 'git worktree remove --force "$lavoro" 2>/dev/null || true; rm -rf "$lavoro"' EXIT

if git show-ref --verify --quiet refs/heads/gh-pages; then
    git worktree add --quiet "$lavoro" gh-pages
elif git ls-remote --exit-code --heads origin gh-pages >/dev/null 2>&1; then
    git fetch --quiet origin gh-pages:gh-pages
    git worktree add --quiet "$lavoro" gh-pages
else
    # Primo sito: branch senza storia, che non condivide nulla con main.
    git worktree add --quiet --detach "$lavoro"
    git -C "$lavoro" checkout --quiet --orphan gh-pages
fi

git -C "$lavoro" rm -r --quiet --force --ignore-unmatch .
cp -R build/site/. "$lavoro"/
git -C "$lavoro" add --all

if git -C "$lavoro" diff --cached --quiet; then
    echo "gh-pages e' gia' aggiornato al sito generato da ${sorgente}."
else
    git -C "$lavoro" commit --quiet -m "sito: edizione ${edizione}

Generato da scripts/build_site.py a partire da ${sorgente}."
    echo "Commit registrato sul branch locale gh-pages: $(git rev-parse --short gh-pages)"
fi

if [ "${1:-}" = "--push" ]; then
    git push origin gh-pages
    echo "Inviato. Prima pubblicazione: attivare Pages in Settings -> Pages (docs/maintainers/github-pages.md)."
else
    echo "Nessun invio a GitHub. Per pubblicare: scripts/publish_site.sh --push"
fi
