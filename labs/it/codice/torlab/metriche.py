# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 15: statistiche della rete da documenti pubblici.

Due strumenti: un riassunto del consenso (relay, flag, banda, versioni, rete /16)
e la stima degli utenti con il metodo di Tor Metrics (richieste di directory / 10).
"""
from __future__ import annotations

import math
from collections import Counter

from .directory import Consenso
from .percorso import rete16


def riassunto(consenso: Consenso) -> dict:
    """Riassume un consenso; le quote sono None se il peso totale è zero."""
    relay = consenso.relay
    banda = sum(r.banda or 0 for r in relay)
    flag = Counter(f for r in relay for f in r.flag)
    exit_ = [r for r in relay if "Exit" in r.flag and "BadExit" not in r.flag]
    guard = [r for r in relay if "Guard" in r.flag]
    return {
        "relay": len(relay),
        # ordine deterministico: a parità di conteggio, per nome (altrimenti dipende
        # dall'ordine di iterazione degli insiemi, diverso a ogni esecuzione di Python)
        "flag": dict(sorted(flag.items(), key=lambda x: (-x[1], x[0]))),
        "banda_totale": banda,
        "quota_banda_exit": (sum(r.banda or 0 for r in exit_) / banda
                                 if banda > 0 else None),
        "quota_banda_guard": (sum(r.banda or 0 for r in guard) / banda
                                  if banda > 0 else None),
        "versioni": sorted(Counter(" ".join(r.versione.split()[:2]) for r in relay).items(),
                            key=lambda x: (-x[1], x[0]))[:5],
        "reti16": sorted(Counter(rete16(r) for r in relay).items(),
                         key=lambda x: (-x[1], x[0]))[:5],
    }


def stima_utenti(richieste_riportate: int, frazione: float) -> int | None:
    """Stima i client Tor mediamente connessi dalle richieste giornaliere.

    r(N) = floor(r(R) / frac / 10); la soglia 10–110% segue Tor Metrics.
    È una stima, non un conteggio diretto delle persone uniche.
    """
    if isinstance(richieste_riportate, bool) or not isinstance(richieste_riportate, int) or richieste_riportate < 0:
        raise ValueError("le richieste devono essere un intero non negativo")
    if isinstance(frazione, bool) or not isinstance(frazione, (int, float)):
        return None
    if not math.isfinite(frazione):
        return None
    if not 0.10 <= frazione <= 1.10:
        return None
    return math.floor(richieste_riportate / frazione / 10)


def togli_arrotondamento(valore: int, passo: int = 8) -> int | None:
    """Compensa l'arrotondamento per eccesso sottraendo metà passo pari.

    dirreq-v3-reqs usa passo 8; per conteggi insufficienti torna None.
    """
    if isinstance(valore, bool) or not isinstance(valore, int) or valore < 0:
        raise ValueError("il valore deve essere un intero non negativo")
    if isinstance(passo, bool) or not isinstance(passo, int) or passo <= 0 or passo % 2:
        raise ValueError("il passo deve essere un intero positivo e pari")
    v = valore - passo // 2
    return v if v > 0 else None


if __name__ == "__main__":
    import sys
    from .directory import analizza_consenso
    with open(sys.argv[1], encoding="utf-8") as source:
        c = analizza_consenso(source.read())
    for k, v in riassunto(c).items():
        print(f"{k}: {v}")
