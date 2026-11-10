# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 7 — selección de rutas.

Referencias: path-spec, restricciones de selección de rutas y ponderación de nodos;
dir-spec, bandwidth-weights. Implementa selección ponderada de salidas, guardias e
intermedios con restricciones esenciales: indicadores, repetidores distintos y redes /16.
Las familias, que requieren microdescriptores, se dejan como ejercicio.
Módulo didáctico: la selección real de tor contempla muchas más reglas, como
guardias persistentes, vanguards, aislamiento de flujos y preferencias de puertos.
"""
from __future__ import annotations

import ipaddress
import math
import random
from dataclasses import dataclass

from .directory import Consensus, RelayEntry

POSITIONS = ("guard", "middle", "exit")


def _check_position(position: str) -> None:
    if position not in POSITIONS:
        raise ValueError("posición de repetidor desconocida")


def _check_scale(scale: int) -> None:
    if isinstance(scale, bool) or not isinstance(scale, int) or not 1 <= scale <= 2 ** 31 - 1:
        raise ValueError("parámetro bwweightscale del consenso no válido")


def _relay_type(r: RelayEntry) -> str:
    """g: solo Guard; e: solo Exit; d: Guard y Exit; m: ninguno."""
    g, e = "Guard" in r.flag, "Exit" in r.flag  # BadExit prohíbe actuar como salida, no modifica la categoría de peso
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]


def weight(r: RelayEntry, position: str, weights: dict[str, int], scale: int = 10000) -> float:
    """Aplica W<posición><tipo> dividido entre bwweightscale del consenso."""
    _check_position(position)
    _check_scale(scale)
    bw = r.bandwidth if r.bandwidth is not None else 0
    if isinstance(bw, bool) or not isinstance(bw, int) or bw < 0:
        raise ValueError("ancho de banda del repetidor no válido")
    factor = weights.get(f"W{position[0]}{_relay_type(r)}", scale)
    if isinstance(factor, bool) or not isinstance(factor, int) or not 0 <= factor <= scale:
        raise ValueError("peso de ancho de banda del consenso no válido")
    return bw * factor / scale

def eligible(r: RelayEntry, position: str) -> bool:
    _check_position(position)
    if not {"Running", "Valid", "Fast"} <= r.flag:
        return False
    if position == "guard":
        return "Guard" in r.flag and "MiddleOnly" not in r.flag
    if position == "exit":
        return "Exit" in r.flag and "BadExit" not in r.flag and "MiddleOnly" not in r.flag
    return True


def network16(r: RelayEntry) -> str:
    """Dos primeros octetos de una dirección IPv4 válida (prefijo /16)."""
    try:
        ip = ipaddress.IPv4Address(r.ip)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError("dirección IPv4 del repetidor no válida") from exc
    return ".".join(str(ip).split(".")[:2])

class Selector:
    """Almacena los repetidores aptos y los pesos por posición.

    Seleccionar entre candidatos válidos evita rechazos por pesos muy pequeños.
    """

    def __init__(self, consensus: Consensus):
        self.scale = consensus.parameters.get("bwweightscale", 10000)
        _check_scale(self.scale)
        self.candidates, self.weights = {}, {}
        for pos in POSITIONS:
            candidates = [r for r in consensus.relay if eligible(r, pos)]
            values = [weight(r, pos, consensus.weights, self.scale) for r in candidates]
            self.candidates[pos] = [r for r, w in zip(candidates, values) if w > 0]
            self.weights[pos] = [w for w in values if w > 0]

    def choose(self, pos: str, excluded: list[RelayEntry], rng: random.Random,
               distinct_networks: bool = True, attempts: int = 1000) -> RelayEntry:
        """Elige candidatos viables; se conserva attempts por compatibilidad."""
        _check_position(pos)
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
            raise ValueError("el número de intentos debe ser positivo")
        excluded_ids = {r.id_rsa for r in excluded}
        excluded_nets = {network16(r) for r in excluded} if distinct_networks else set()
        pairs = [(r, w) for r, w in zip(self.candidates[pos], self.weights[pos])
                 if r.id_rsa not in excluded_ids
                 and (not distinct_networks or network16(r) not in excluded_nets)]
        if not pairs:
            raise LookupError(f"no hay repetidores aptos para la posición {pos}")
        return rng.choices([r for r, _ in pairs], weights=[w for _, w in pairs])[0]

    def path(self, rng: random.Random, guard: RelayEntry | None = None,
             distinct_networks: bool = True) -> tuple[RelayEntry, RelayEntry, RelayEntry]:
        """Primero Exit, luego un Guard validado y, finalmente, el nodo intermedio."""
        if guard is not None:
            guard = next((r for r in self.candidates["guard"]
                          if r.id_rsa == guard.id_rsa), None)
            if guard is None:
                raise LookupError("el Guard fijado no pertenece a los candidatos aptos")
        e = self.choose("exit", [guard] if guard is not None else [], rng, distinct_networks)
        g = guard if guard is not None else self.choose("guard", [e], rng, distinct_networks)
        m = self.choose("middle", [e, g], rng, distinct_networks)
        return g, m, e

def probabilities(consensus: Consensus, position: str) -> dict[str, float]:
    """Probabilidades ponderadas sin políticas de salida ni restricciones de subred."""
    _check_position(position)
    scale = consensus.parameters.get("bwweightscale", 10000)
    _check_scale(scale)
    weights: dict[str, float] = {}
    for r in consensus.relay:
        if eligible(r, position):
            w = weight(r, position, consensus.weights, scale)
            if w > 0:
                name = r.name + ":" + r.id_rsa.hex()
                weights[name] = weights.get(name, 0.0) + w
    total = sum(weights.values())
    return {name: w / total for name, w in weights.items()} if total else {}

def top_share(prob: dict[str, float], n: int) -> float:
    """Cuota de las n probabilidades mayores (cero si n es cero)."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("n debe ser un entero no negativo")
    if any(isinstance(p, bool) or not isinstance(p, (float, int)) or
           not math.isfinite(p) or not 0 <= p <= 1 for p in prob.values()):
        raise ValueError("probabilidad de repetidor no válida")
    return sum(sorted(prob.values(), reverse=True)[:n])

@dataclass
class Adversary:
    """Modelo didáctico de circuitos independientes; no modela Guard persistentes."""
    guard_share: float
    exit_share: float

    def __post_init__(self) -> None:
        for fraction in (self.guard_share, self.exit_share):
            if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not math.isfinite(fraction) or not 0 <= fraction <= 1:
                raise ValueError("las fracciones adversarias deben ser finitas entre 0 y 1")

    def compromised_circuits(self, circuits: int, fixed_guard: bool) -> float:
        """Probabilidad de que al menos un circuito utilice Guard y Exit adversarios."""
        if isinstance(circuits, bool) or not isinstance(circuits, int) or circuits < 0:
            raise ValueError("el número de circuitos debe ser un entero no negativo")
        fraction = self.guard_share * self.exit_share
        if not fixed_guard:
            return 1 - (1 - fraction) ** circuits
        return self.guard_share * (1 - (1 - self.exit_share) ** circuits)
