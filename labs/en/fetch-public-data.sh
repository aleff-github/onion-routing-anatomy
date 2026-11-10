#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Source: Tor Project CollecTor; the downloaded consensus is technical data,
# not translated content. Download happens only when explicitly requested.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$ROOT/data/collector"
TARGET="2026-09-23-15-00-00-consensus-microdesc"
DEST="$OUT/consensus-microdesc-2026-09-23-15"
ARCHIVE_URL="https://collector.torproject.org/archive/relay-descriptors/microdescs/microdescs-2026-09.tar.xz"

# Header format only; this does not verify signatures or authority certificates.
header_ok() {
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
  if ! header_ok "$DEST"; then
    echo "Existing file does not have the expected microdescriptor consensus header; inspect it before rerunning: $DEST" >&2
    exit 1
  fi
  echo "Historical CollecTor consensus already available: $DEST"
  exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar with xz support is required" >&2; exit 1; }

tmp=$(mktemp)
tmpdest=$(mktemp "$OUT/.consensus-microdesc.XXXXXX")
trap 'rm -f "$tmp" "$tmpdest"' EXIT HUP INT TERM

echo "Downloading the September 2026 public CollecTor archive"
curl --fail --location --retry 3 --output "$tmp" "$ARCHIVE_URL"
member=$(tar -tJf "$tmp" | awk -v target="$TARGET" '
  $0 == target || $0 ~ ("/" target "$") { print; exit }
')
if [ -z "$member" ]; then
  echo "The requested historical consensus was not found in the archive: $TARGET" >&2
  exit 1
fi
tar -xJOf "$tmp" "$member" > "$tmpdest"
if ! header_ok "$tmpdest"; then
  echo "The extracted file lacks the expected Tor microdescriptor consensus format header" >&2
  exit 1
fi
mv "$tmpdest" "$DEST"
echo "Public research snapshot prepared: $DEST"
echo "Source archive: $ARCHIVE_URL"
