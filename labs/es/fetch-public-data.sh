#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Fuente: Tor Project CollecTor; el consenso descargado son datos técnicos,
# no contenido traducible. Solo se descarga cuando se solicita.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$ROOT/datos/collector"
TARGET="2026-09-23-15-00-00-consensus-microdesc"
DEST="$OUT/consensus-microdesc-2026-09-23-15"
ARCHIVE_URL="https://collector.torproject.org/archive/relay-descriptors/microdescs/microdescs-2026-09.tar.xz"

# Solo se comprueba la cabecera de formato; no se validan firmas ni certificados de autoridades.
cabecera_valida() {
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
  if ! cabecera_valida "$DEST"; then
    echo "El archivo existente no tiene la cabecera esperada; revísalo antes de repetir la operación: $DEST" >&2
    exit 1
  fi
  echo "Ya está disponible el consenso histórico de CollecTor: $DEST"
  exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "Se necesita curl para descargar el archivo" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "Se necesita tar con soporte xz" >&2; exit 1; }

tmp=$(mktemp)
tmpdest=$(mktemp "$OUT/.consensus-microdesc.XXXXXX")
trap 'rm -f "$tmp" "$tmpdest"' EXIT HUP INT TERM

echo "Descargando el archivo público de CollecTor de septiembre de 2026"
curl --fail --location --retry 3 --output "$tmp" "$ARCHIVE_URL"
member=$(tar -tJf "$tmp" | awk -v target="$TARGET" '
  $0 == target || $0 ~ ("/" target "$") { print; exit }
')
if [ -z "$member" ]; then
  echo "No se encontró el consenso histórico solicitado dentro del archivo: $TARGET" >&2
  exit 1
fi
tar -xJOf "$tmp" "$member" > "$tmpdest"
if ! cabecera_valida "$tmpdest"; then
  echo "El archivo extraído carece de la cabecera de formato esperada del consenso microdesc de Tor" >&2
  exit 1
fi
mv "$tmpdest" "$DEST"
echo "Preparada la instantánea pública de investigación: $DEST"
echo "Archivo de origen: $ARCHIVE_URL"
