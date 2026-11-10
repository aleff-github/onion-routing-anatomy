#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
#
# Crea (o aggiorna) le etichette usate dai moduli di .github/ISSUE_TEMPLATE e dal processo
# editoriale (docs/editorial-process.md). Richiede il comando gh autenticato con permessi di
# amministrazione sulla repository. Da eseguire una volta; rieseguirlo non duplica nulla.
set -eu
repo=${1:-aleff-github/onion-routing-anatomy}

while IFS='|' read -r nome colore descrizione; do
    codificato=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$nome")
    if gh api "repos/$repo/labels/$codificato" >/dev/null 2>&1; then
        gh api -X PATCH "repos/$repo/labels/$codificato" -f color="$colore" -f description="$descrizione" >/dev/null
    else
        gh api -X POST "repos/$repo/labels" -f name="$nome" -f color="$colore" -f description="$descrizione" >/dev/null
    fi
    echo "$nome"
done <<'ETICHETTE'
typo|d4c5f9|Typo or wording · Refuso o formulazione
translation|bfdadc|Translation problem · Errore di traduzione
technical|b60205|Technical correction · Correzione tecnica
laboratory|0e8a16|Laboratory problem · Problema di laboratorio
documentation|0075ca|Documentation · Documentazione
proposal|a2eeef|Content or feature proposal · Proposta
status: to verify|fbca04|Da verificare
status: confirmed|d93f0b|Confermata
status: in progress|1d76db|In lavorazione
status: fix proposed|5319e7|Correzione proposta
status: resolved|0e8a16|Risolta
status: not reproducible|cfd3d7|Non riproducibile
status: duplicate|cfd3d7|Duplicata
lang: it|ededed|Italiano (original)
lang: en|ededed|English
lang: es|ededed|Español
lang: ru|ededed|Русский
lang: zh-Hans|ededed|简体中文
ETICHETTE
