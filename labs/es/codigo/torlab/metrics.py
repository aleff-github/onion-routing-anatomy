# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 15: estadísticas de red a partir de documentos públicos.

Dos herramientas: resumen del consenso (repetidores, indicadores, ancho de banda,
versiones, redes /16) y estimación de usuarios de Tor Metrics (solicitudes / 10).
"""
from __future__ import annotations

import math
from collections import Counter

from .directory import Consensus
from .path_selection import network16


def summary(consensus: Consensus) -> dict:
    """Resume un consenso; las cuotas son None si el peso total es cero."""
    relay = consensus.relay
    bandwidth = sum(r.bandwidth or 0 for r in relay)
    flag = Counter(f for r in relay for f in r.flag)
    exit_ = [r for r in relay if "Exit" in r.flag and "BadExit" not in r.flag]
    guard = [r for r in relay if "Guard" in r.flag]
    return {
        "relay": len(relay),
        # Orden determinista: ante un empate se ordena por nombre; de lo contrario,
        # el resultado dependería del orden del conjunto entre ejecuciones.
        "flag": dict(sorted(flag.items(), key=lambda x: (-x[1], x[0]))),
        "total_bandwidth": bandwidth,
        "exit_bandwidth_share": (sum(r.bandwidth or 0 for r in exit_) / bandwidth
                                 if bandwidth > 0 else None),
        "guard_bandwidth_share": (sum(r.bandwidth or 0 for r in guard) / bandwidth
                                  if bandwidth > 0 else None),
        "versions": sorted(Counter(" ".join(r.version.split()[:2]) for r in relay).items(),
                            key=lambda x: (-x[1], x[0]))[:5],
        "networks16": sorted(Counter(network16(r) for r in relay).items(),
                         key=lambda x: (-x[1], x[0]))[:5],
    }


def estimate_users(reported_requests: int, fraction: float) -> int | None:
    """Estima clientes Tor concurrentes medios a partir de solicitudes diarias.

    r(N) = floor(r(R) / frac / 10); umbral de cobertura de 10–110%.
    Es una estimación, no un recuento directo de personas únicas.
    """
    if isinstance(reported_requests, bool) or not isinstance(reported_requests, int) or reported_requests < 0:
        raise ValueError("las solicitudes deben ser un entero no negativo")
    if isinstance(fraction, bool) or not isinstance(fraction, (int, float)):
        return None
    if not math.isfinite(fraction):
        return None
    if not 0.10 <= fraction <= 1.10:
        return None
    return math.floor(reported_requests / fraction / 10)


def remove_rounding(value: int, step: int = 8) -> int | None:
    """Deshace el redondeo al alza restando medio paso positivo y par.

    dirreq-v3-reqs usa paso 8; los valores demasiado pequeños dan None.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("el valor debe ser un entero no negativo")
    if isinstance(step, bool) or not isinstance(step, int) or step <= 0 or step % 2:
        raise ValueError("el paso debe ser un entero positivo y par")
    v = value - step // 2
    return v if v > 0 else None


if __name__ == "__main__":
    import sys
    from .directory import parse_consensus
    with open(sys.argv[1], encoding="utf-8") as source:
        c = parse_consensus(source.read())
    labels = {
        "relay": "repetidores",
        "flag": "indicadores",
        "total_bandwidth": "peso total de ancho de banda",
        "exit_bandwidth_share": "cuota de peso de salida",
        "guard_bandwidth_share": "cuota de peso de entrada",
        "versions": "versiones",
        "networks16": "redes /16",
    }
    for k, v in summary(c).items():
        print(f"{labels.get(k, k)}: {v}")
