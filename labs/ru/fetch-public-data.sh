#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Источник: Tor Project CollecTor; загруженный консенсус — технические данные,
# а не переводимый текст. Загрузка выполняется только по запросу.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$ROOT/данные/collector"
TARGET="2026-09-23-15-00-00-consensus-microdesc"
DEST="$OUT/consensus-microdesc-2026-09-23-15"
ARCHIVE_URL="https://collector.torproject.org/archive/relay-descriptors/microdescs/microdescs-2026-09.tar.xz"

# Проверяется только заголовок формата: подписи и сертификаты центров не проверяются.
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
    echo "Существующий файл имеет неверный заголовок; проверьте его перед повторным запуском: $DEST" >&2
    exit 1
  fi
  echo "Исторический консенсус CollecTor уже подготовлен: $DEST"
  exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "Для загрузки требуется curl" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "Требуется tar с поддержкой xz" >&2; exit 1; }

tmp=$(mktemp)
tmpdest=$(mktemp "$OUT/.consensus-microdesc.XXXXXX")
trap 'rm -f "$tmp" "$tmpdest"' EXIT HUP INT TERM

echo "Загрузка общедоступного архива CollecTor за сентябрь 2026 года"
curl --fail --location --retry 3 --output "$tmp" "$ARCHIVE_URL"
member=$(tar -tJf "$tmp" | awk -v target="$TARGET" '
  $0 == target || $0 ~ ("/" target "$") { print; exit }
')
if [ -z "$member" ]; then
  echo "Нужный исторический консенсус не найден в архиве: $TARGET" >&2
  exit 1
fi
tar -xJOf "$tmp" "$member" > "$tmpdest"
if ! header_ok "$tmpdest"; then
  echo "В извлечённом файле отсутствует ожидаемый заголовок формата консенсуса Tor microdesc" >&2
  exit 1
fi
mv "$tmpdest" "$DEST"
echo "Публичные исследовательские данные подготовлены: $DEST"
echo "Исходный архив: $ARCHIVE_URL"
