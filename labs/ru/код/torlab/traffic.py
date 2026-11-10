# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 12 — чтение ячеек из записанного и расшифрованного канала.

Исходные данные — вывод `tshark -q -z follow,tls,raw,N` для захвата *своего*
канала, расшифрованного с помощью ключей, экспортированных через SSLKEYLOGFILE (глава 20).
"""
from __future__ import annotations

from .cells import Cell, CellCommand, decode


def cells_from_follow(text: str) -> list[tuple[str, Cell, int]]:
    """Возвращает (направление, ячейка, версия разбора) для обоих направлений.
    В этой учебной трассе первый блок — VERSIONS клиента; tshark выделяет одно направление
    отступом табуляции. После каждой VERSIONS разбор использует версию канала 5
    (CircID размером 4 байта), не вычисляя фактически согласованную версию
    по спискам версий, предложенным обеими сторонами."""
    lines = [r for r in text.splitlines()
             if r.strip() and not r.startswith(("=", "Follow", "Filter", "Node"))]
    if not lines:
        return []
    client_indented = lines[0].startswith("\t")
    version = {"client": 0, "relay": 0}
    remaining = {"client": b"", "relay": b""}
    output = []
    for r in lines:
        direction = "client" if r.startswith("\t") == client_indented else "relay"
        remaining[direction] += bytes.fromhex(r.strip())
        while (x := decode(remaining[direction], version[direction])) is not None:
            cell, remaining[direction] = x
            output.append((direction, cell, version[direction]))
            if cell.command == CellCommand.VERSIONS and version[direction] == 0:
                version[direction] = 5
    return output
