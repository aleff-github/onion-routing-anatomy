# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 19 — primera desanonimización en un modelo TorPS simplificado.

Un adversario controla cuotas fijas de banda ponderada para Guard y Exit.
Cada cliente simulado construye un número fijo de circuitos por día, con un
Guard persistente durante un plazo didáctico o uno nuevo en cada circuito.
Se considera comprometido cuando un circuito usa Guard y Exit adversarios.
No se modelan los nodos intermedios, prioridad de los Guard, fallos,
familias, IPv6 o dependencias entre caminos.

Los valores por defecto de guard-spec son 120 días para Guard sin confirmar
y 60 para Guard confirmados, con reglas adicionales de muestras y fechas.
El rango 48–60 días aquí es una **aproximación didáctica**, no el ciclo de
vida exacto de Tor ni una predicción real de anonimato.
"""
from __future__ import annotations

import bisect
import itertools
import math
import random
from dataclasses import dataclass
from pathlib import Path

from .directory import Consensus
from .path_selection import eligible, weight

GUARD_LIFETIME = 120                  # Vida predeterminada de Guard sin confirmar (días)
GUARD_CONFIRMED_MIN_LIFETIME = 60     # Vida mínima de Guard confirmado (días)
BACKDATE = GUARD_LIFETIME // 10       # Máximo ajuste retroactivo en el modelo didáctico


def _positive_int(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} debe ser un entero positivo")


def _guard_lifetime(rng: random.Random, lifetime: int) -> int:
    """Vida aproximada de Guard con retroactividad limitada a valores positivos."""
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime < 1:
        raise ValueError("la vida del Guard debe ser un entero positivo")
    return lifetime - rng.randint(0, min(BACKDATE, lifetime - 1))


class WeightedUrn:
    """Muestreo ponderado validado con cuota adversaria explícita."""

    def __init__(self, weights: list[float], adversary_share: float):
        if isinstance(adversary_share, bool) or not isinstance(adversary_share, (int, float)) or not math.isfinite(adversary_share) or not 0 <= adversary_share <= 1:
            raise ValueError("la cuota adversaria debe ser una fracción finita entre 0 y 1")
        if any(isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or w < 0 for w in weights):
            raise ValueError("los pesos deben ser números finitos no negativos")
        self.n = len(weights)
        self.all_adversarial = adversary_share == 1
        if self.all_adversarial:
            self.cumulative = []
            return
        max_weight = max(weights, default=0.0)
        if max_weight <= 0:
            raise ValueError("se necesita al menos un repetidor honesto con peso positivo")
        scaled = [w / max_weight for w in weights]
        total = math.fsum(scaled)
        if not math.isfinite(total) or total <= 0:
            raise ValueError("se necesita al menos un repetidor honesto con peso positivo")
        honest = 1.0 - adversary_share
        # Normalizar primero por el peso máximo para evitar desbordamientos.
        normalized = [w / total * honest for w in scaled]
        self.cumulative = list(itertools.accumulate(normalized + [adversary_share]))

    def adversarial(self, rng: random.Random) -> bool:
        """Indica si la muestra corresponde al adversario."""
        if self.all_adversarial:
            return True
        x = rng.random() * self.cumulative[-1]
        return bisect.bisect_right(self.cumulative, x) >= self.n


@dataclass
class Result:
    """Día de primer compromiso por cliente; None representa censura."""
    days_to_compromise: list[int | None]

    def fraction_by(self, day: int) -> float:
        """Porción de clientes comprometidos hasta el día indicado."""
        if isinstance(day, bool) or not isinstance(day, int) or day < 0:
            raise ValueError("el día debe ser un entero no negativo")
        if not self.days_to_compromise:
            raise ValueError("el resultado de la simulación no contiene clientes")
        return sum(1 for d in self.days_to_compromise if d is not None and d <= day) / len(self.days_to_compromise)

    def median(self) -> int | None:
        """Primer día en que al menos la mitad de los clientes está comprometida."""
        if not self.days_to_compromise:
            return None
        compromised = sorted(d for d in self.days_to_compromise if d is not None)
        needed = (len(self.days_to_compromise) + 1) // 2
        return compromised[needed - 1] if len(compromised) >= needed else None


def simulate(consensus: Consensus, guard_share: float, exit_share: float, *, client: int = 2000,
           days: int = 180, circuits: int = 20, persistent_guard: bool = True,
           guard_lifetime: int = GUARD_CONFIRMED_MIN_LIFETIME, seed: int = 1) -> Result:
    """Aproximación didáctica Monte Carlo, no pronóstico de anonimato real."""
    for label, value in (("client", client), ("days", days),
                         ("circuits", circuits), ("guard_lifetime", guard_lifetime)):
        _positive_int(value, label)
    scale = consensus.parameters.get("bwweightscale", 10000)
    rng = random.Random(seed)
    guard_weights = [weight(r, "guard", consensus.weights, scale) for r in consensus.relay if eligible(r, "guard")]
    exit_weights = [weight(r, "exit", consensus.weights, scale) for r in consensus.relay if eligible(r, "exit")]
    guard = WeightedUrn(guard_weights, guard_share)
    exit_ = WeightedUrn(exit_weights, exit_share)
    results: list[int | None] = []
    for _ in range(client):
        compromised = None
        if persistent_guard:
            guard_adversarial = guard.adversarial(rng)
            expiration = _guard_lifetime(rng, guard_lifetime)
        for day in range(1, days + 1):
            if persistent_guard and day > expiration:
                guard_adversarial = guard.adversarial(rng)
                expiration = day + _guard_lifetime(rng, guard_lifetime) - 1
            for _ in range(circuits):
                g = guard_adversarial if persistent_guard else guard.adversarial(rng)
                if g and exit_.adversarial(rng):
                    compromised = day
                    break
            if compromised is not None:
                break
        results.append(compromised)
    return Result(results)


if __name__ == "__main__":
    import sys
    from .directory import parse_consensus

    if len(sys.argv) < 2:
        raise SystemExit("Uso: python -m torlab.simulation ARCHIVO_CONSENSO [CUOTA_ADVERSARIA]")
    path = Path(sys.argv[1])
    c = parse_consensus(path.read_text(encoding="utf-8"))
    q = float(sys.argv[2]) if len(sys.argv) > 2 else 0.01
    print(f"adversario: {q:.0%} de la banda Guard y {q:.0%} de la banda Exit; 2000 clientes, 180 días, 20 circuitos/día")
    for persistent in (True, False):
        result = simulate(c, q, q, persistent_guard=persistent)
        summary = "  ".join(f"{d:>3}d: {result.fraction_by(d):5.1%}" for d in (1, 7, 30, 90, 180))
        label = ("Guard persistente" if persistent else "Guard por circuito")
        print(f"{label:19s} {summary}  mediana: {result.median()}")
