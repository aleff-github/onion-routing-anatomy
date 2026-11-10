# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratory 12 — read cells from a captured and decrypted channel.

Start from the output of `tshark -q -z follow,tls,raw,N` on a capture of your *own*
channel, decrypted with keys exported through SSLKEYLOGFILE (Chapter 20).
"""
from __future__ import annotations

from .cells import Cell, CellCommand, decode


def cells_from_follow(text: str) -> list[tuple[str, Cell, int]]:
    """Return (direction, cell, parsing version) for both directions.
    In this teaching trace the first block is the client's VERSIONS; tshark tabs one direction.
    After each VERSIONS the parser assumes link version 5 (a 4-byte CircID).
    It does not derive the actually negotiated version from both peers' offers."""
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
