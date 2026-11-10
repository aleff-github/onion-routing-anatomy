# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 12 — leer celdas de un canal capturado y descifrado.

Parte de la salida de `tshark -q -z follow,tls,raw,N` de una captura de tu
*propio* canal, descifrada con claves exportadas mediante SSLKEYLOGFILE (capítulo 20).
"""
from __future__ import annotations

from .cells import Cell, CellCommand, decode


def cells_from_follow(text: str) -> list[tuple[str, Cell, int]]:
    """Devuelve (dirección, celda, versión usada al analizar) para ambos sentidos.
    En esta traza didáctica el primer bloque es VERSIONS del cliente; tshark tabula un sentido.
    Tras cada VERSIONS se presupone la versión de enlace 5 (CircID de 4 bytes).
    No se calcula la versión realmente negociada a partir de las ofertas de ambos pares.
    Los valores «client» y «relay» se mantienen por compatibilidad con la API."""
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
