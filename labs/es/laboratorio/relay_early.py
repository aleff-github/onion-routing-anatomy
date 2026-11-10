#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 17 — límite de RELAY_EARLY en el repetidor privado 004r.

Envía 8 o 9 celdas RELAY_EARLY sobre un circuito nuevo en la red Chutney.
La novena supera deliberadamente el límite. Los mensajes DROP dentro de
RELAY_EARLY no cumplen la regla del cliente Tor; este test solo reproduce
una observación histórica, sin garantizar un DESTROY ni el motivo 1.
Nunca utilizar repetidores públicos.
"""
from __future__ import annotations

import argparse

from torlab.cells import Cell, CellCommand, RelayCommand, RelayMessage
from torlab.circuit import CircuitError, MAX_RELAY_EARLY, build
from torlab.laboratory import relay


def validar_cantidad(cantidad: int) -> int:
    """Permite únicamente los dos casos de comparación del experimento."""
    if (isinstance(cantidad, bool) or not isinstance(cantidad, int)
            or cantidad not in (MAX_RELAY_EARLY, MAX_RELAY_EARLY + 1)):
        raise ValueError("Solo se permiten 8 o 9 celdas en la red privada")
    return cantidad


def enviar_tempranas(circuito, cantidad: int) -> None:
    """Omite el límite local del cliente para comprobar la defensa del repetidor."""
    validar_cantidad(cantidad)
    for _ in range(cantidad):
        cuerpo = circuito.crypto.encrypt(RelayMessage(RelayCommand.DROP, 0), None)
        circuito.channel.send(Cell(circuito.circ_id, CellCommand.RELAY_EARLY, cuerpo))


def evaluar_respuesta(cantidad: int, respuesta: str) -> bool:
    """Compara la respuesta con el patrón histórico, sin afirmar un MUST de Tor."""
    validar_cantidad(cantidad)
    if cantidad == MAX_RELAY_EARLY:
        return respuesta == "CONNECTED"
    return respuesta == "circuito destruido, motivo 1"


def probar_cantidad(cantidad: int) -> str:
    """Construye un circuito de un salto al repetidor privado 004r."""
    validar_cantidad(cantidad)
    circuito = build([relay("004r")], cc=False)
    try:
        # Prueba deliberadamente no conforme: DROP dentro de RELAY_EARLY.
        enviar_tempranas(circuito, cantidad)
        circuito.send(RelayMessage(RelayCommand.BEGIN_DIR, 1))
        _, respuesta = circuito.receive()
        return RelayCommand(respuesta.command).name
    except CircuitError as exc:
        # torlab.circuit de la edición española ya genera mensajes localizados.
        return str(exc)
    finally:
        circuito.channel.sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Comprobar el límite RELAY_EARLY solo en Chutney privado"
    )
    parser.add_argument("cantidades", type=int, nargs="*", default=[8, 9],
                        help="Únicamente 8 y/o 9 celdas")
    args = parser.parse_args()
    if len(args.cantidades) != len(set(args.cantidades)):
        parser.error("No se permiten cantidades repetidas")
    for cantidad in args.cantidades:
        try:
            validar_cantidad(cantidad)
        except ValueError as exc:
            parser.error(str(exc))
    correctos = []
    for cantidad in args.cantidades:
        resultado = probar_cantidad(cantidad)
        correcto = evaluar_respuesta(cantidad, resultado)
        correctos.append(correcto)
        print(f"{cantidad} celdas RELAY_EARLY -> {resultado}")
        print(f"Comprobación: {'CORRECTA' if correcto else 'NO VERIFICADA'}")
    return 0 if all(correctos) else 1


if __name__ == "__main__":
    raise SystemExit(main())
