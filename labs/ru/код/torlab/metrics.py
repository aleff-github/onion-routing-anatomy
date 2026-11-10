# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 15: статистика сети по публичным документам.

Два инструмента: сводка consensus (relay, flags, bandwidth, versions, сети /16)
и оценка числа пользователей Tor Metrics (directory requests / 10).
"""
from __future__ import annotations

import math
from collections import Counter

from .directory import Consensus
from .path_selection import network16


def summary(consensus: Consensus) -> dict:
    """Сводка одного консенсуса; при нулевом весе доли равны None."""
    relay = consensus.relay
    bandwidth = sum(r.bandwidth or 0 for r in relay)
    flag = Counter(f for r in relay for f in r.flag)
    exit_ = [r for r in relay if "Exit" in r.flag and "BadExit" not in r.flag]
    guard = [r for r in relay if "Guard" in r.flag]
    return {
        "relay": len(relay),
        # Детерминированный порядок: при равных счётчиках сортировать по имени
        # (иначе результат зависит от порядка обхода множеств при запусках Python).
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
    """Оценить среднее число одновременно работающих клиентов по запросам за день.

    r(N) = floor(r(R) / frac / 10); пороги доли 10–110% взяты из Tor Metrics.
    Это оценка, а не подсчёт уникальных людей.
    """
    if isinstance(reported_requests, bool) or not isinstance(reported_requests, int) or reported_requests < 0:
        raise ValueError("число запросов должно быть неотрицательным целым")
    if isinstance(fraction, bool) or not isinstance(fraction, (int, float)):
        return None
    if not math.isfinite(fraction):
        return None
    if not 0.10 <= fraction <= 1.10:
        return None
    return math.floor(reported_requests / fraction / 10)


def remove_rounding(value: int, step: int = 8) -> int | None:
    """Убрать округление вверх, вычитая половину положительного чётного шага.

    Для dirreq-v3-reqs шаг равен 8; слишком малые значения дают None.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("значение должно быть неотрицательным целым")
    if isinstance(step, bool) or not isinstance(step, int) or step <= 0 or step % 2:
        raise ValueError("шаг должен быть положительным чётным целым")
    v = value - step // 2
    return v if v > 0 else None


if __name__ == "__main__":
    import sys
    from .directory import parse_consensus
    with open(sys.argv[1], encoding="utf-8") as source:
        c = parse_consensus(source.read())
    labels = {
        "relay": "ретрансляторы",
        "flag": "флаги",
        "total_bandwidth": "общая пропускная способность",
        "exit_bandwidth_share": "доля пропускной способности выходных узлов",
        "guard_bandwidth_share": "доля пропускной способности сторожевых узлов",
        "versions": "версии",
        "networks16": "сети /16",
    }
    for k, v in summary(c).items():
        print(f"{labels.get(k, k)}: {v}")
