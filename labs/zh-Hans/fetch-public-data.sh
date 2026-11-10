#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 简体中文：显式下载 2026-09-23 15:00 UTC 的公共共识。
# 不翻译原始网络文档。仅在读者主动调用 make data 时连接网络。
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$ROOT/数据/collector"
TARGET="2026-09-23-15-00-00-consensus-microdesc"
DEST="$OUT/consensus-microdesc-2026-09-23-15"
ARCHIVE_URL="https://collector.torproject.org/archive/relay-descriptors/microdescs/microdescs-2026-09.tar.xz"

# 仅检查格式标头；不验证共识签名或目录权威证书。
header_ok() {
    [ -s "$1" ] || return 1
    first=$(sed -n '1p' "$1")
    case "$first" in
        "@type network-status-microdesc-consensus-3 "*)
            second=$(sed -n '2p' "$1")
            case "$second" in "network-status-version 3 microdesc"*) return 0;; esac
            ;;
        "network-status-version 3 microdesc"*) return 0;;
    esac
    return 1
}

mkdir -p "$OUT"
if [ -e "$DEST" ]; then
    if ! header_ok "$DEST"; then
        echo "错误：已有文件不符合预期的微描述符共识标头格式；请先检查：$DEST" >&2
        exit 1
    fi
    echo "历史 CollecTor 共识已存在：$DEST"
    exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "错误：需要 curl 下载归档。" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "错误：需要支持 xz 的 tar。" >&2; exit 1; }

tmp=$(mktemp)
tmpdest=$(mktemp "$OUT/.consensus-microdesc.XXXXXX")
trap 'rm -f "$tmp" "$tmpdest"' EXIT HUP INT TERM

echo "正在下载 Tor Project CollecTor 2026 年 9 月归档"
curl --fail --location --retry 3 --output "$tmp" "$ARCHIVE_URL"

member=$(tar -tJf "$tmp" | awk -v target="$TARGET" '
    $0 == target || $0 ~ ("/" target "$") { print; exit }
')
if [ -z "$member" ]; then
    echo "错误：归档内没有 $TARGET。" >&2
    exit 1
fi

tar -xJOf "$tmp" "$member" > "$tmpdest"
if ! header_ok "$tmpdest"; then
    echo "错误：归档提取结果缺少预期的微描述符共识标头。" >&2
    exit 1
fi
mv "$tmpdest" "$DEST"
echo "已准备：$DEST"
echo "来源：$ARCHIVE_URL"
