#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Scarica il consenso pubblico storico usato dai Laboratori 7, 15 e 19
# (capitoli 13, 24 e 29) dall'archivio CollecTor del Tor Project.
# Viene eseguito solo su richiesta esplicita (make -C labs/it data): né i test né la
# compilazione del libro scaricano nulla.
#
# ATTENZIONE: lo script controlla soltanto l'intestazione del formato. NON verifica le
# firme delle autorità né i loro certificati: un file con l'intestazione giusta non è per
# questo autentico. Per verificarne le firme serve il Laboratorio 6 (directory.py) con i
# certificati delle autorità.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$ROOT/dati/collector"
TARGET="2026-09-23-15-00-00-consensus-microdesc"
DEST="$OUT/consensus-microdesc-2026-09-23-15"
ARCHIVE_URL="https://collector.torproject.org/archive/relay-descriptors/microdescs/microdescs-2026-09.tar.xz"

# Controlla soltanto l'intestazione del formato; nessuna verifica crittografica.
intestazione_valida() {
  first=$(sed -n '1p' "$1")
  case "$first" in
    "@type network-status-microdesc-consensus-3 "*)
      second=$(sed -n '2p' "$1")
      case "$second" in "network-status-version 3 microdesc"*) return 0;; esac ;;
    "network-status-version 3 microdesc"*) return 0;;
  esac
  return 1
}

mkdir -p "$OUT"
if [ -s "$DEST" ]; then
  if ! intestazione_valida "$DEST"; then
    echo "Il file esistente non ha l'intestazione attesa; controllalo prima di ripetere l'operazione: $DEST" >&2
    exit 1
  fi
  echo "Il consenso storico di CollecTor è già disponibile: $DEST"
  exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "Serve curl per scaricare l'archivio" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "Serve tar con supporto xz" >&2; exit 1; }

tmp=$(mktemp)
tmpdest=$(mktemp "$OUT/.consensus-microdesc.XXXXXX")
trap 'rm -f "$tmp" "$tmpdest"' EXIT HUP INT TERM

echo "Scarico l'archivio pubblico di CollecTor di settembre 2026"
curl --fail --location --retry 3 --output "$tmp" "$ARCHIVE_URL"
member=$(tar -tJf "$tmp" | awk -v target="$TARGET" '
  $0 == target || $0 ~ ("/" target "$") { print; exit }
')
if [ -z "$member" ]; then
  echo "Il consenso richiesto non è presente nell'archivio: $TARGET" >&2
  exit 1
fi
tar -xJOf "$tmp" "$member" > "$tmpdest"
if ! intestazione_valida "$tmpdest"; then
  echo "Il file estratto non ha l'intestazione di un consenso microdesc di Tor" >&2
  exit 1
fi
mv "$tmpdest" "$DEST"
echo "Consenso storico pronto: $DEST"
echo "Archivio di origine: $ARCHIVE_URL"
echo "Nota: è stata controllata solo l'intestazione, non le firme delle autorità."
