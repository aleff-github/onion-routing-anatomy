# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 7 — выбор маршрута.

Источники: path-spec — выбор маршрута и ограничения, взвешивание узлов;
dir-spec — bandwidth-weights. Реализован учебный выбор выходных, входных и
промежуточных узлов с исключением повторов и общих подсетей IPv4 /16.
Семейства ретрансляторов оставлены для отдельного упражнения; реальные клиенты
также используют постоянные Guard, изоляцию потоков и правила выходных портов.
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
        raise ValueError("неизвестная позиция ретранслятора")


def _check_scale(scale: int) -> None:
    if isinstance(scale, bool) or not isinstance(scale, int) or not 1 <= scale <= 2 ** 31 - 1:
        raise ValueError("недопустимый параметр bwweightscale консенсуса")


def _relay_type(r: RelayEntry) -> str:
    """g — только Guard; e — только Exit; d — Guard и Exit; m — ни один."""
    g, e = "Guard" in r.flag, "Exit" in r.flag  # BadExit запрещает выход, но не меняет весовую категорию
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]


def weight(r: RelayEntry, position: str, weights: dict[str, int], scale: int = 10000) -> float:
    """Применяет W<позиция><тип> с делением на bwweightscale консенсуса."""
    _check_position(position)
    _check_scale(scale)
    bw = r.bandwidth if r.bandwidth is not None else 0
    if isinstance(bw, bool) or not isinstance(bw, int) or bw < 0:
        raise ValueError("недопустимая пропускная способность ретранслятора")
    factor = weights.get(f"W{position[0]}{_relay_type(r)}", scale)
    if isinstance(factor, bool) or not isinstance(factor, int) or not 0 <= factor <= scale:
        raise ValueError("недопустимый вес пропускной способности консенсуса")
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
    """Два первых октета корректного IPv4-адреса (префикс /16)."""
    try:
        ip = ipaddress.IPv4Address(r.ip)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError("недопустимый IPv4-адрес ретранслятора") from exc
    return ".".join(str(ip).split(".")[:2])

class Selector:
    """Для каждой позиции сохраняет подходящие ретрансляторы и их веса.

    Выбор среди допустимых альтернатив исключает ложный отказ при малом весе.
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
        """Выбирает из допустимых узлов; параметр attempts оставлен для совместимости."""
        _check_position(pos)
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
            raise ValueError("число попыток должно быть положительным")
        excluded_ids = {r.id_rsa for r in excluded}
        excluded_nets = {network16(r) for r in excluded} if distinct_networks else set()
        pairs = [(r, w) for r, w in zip(self.candidates[pos], self.weights[pos])
                 if r.id_rsa not in excluded_ids
                 and (not distinct_networks or network16(r) not in excluded_nets)]
        if not pairs:
            raise LookupError(f"нет подходящего ретранслятора для позиции {pos}")
        return rng.choices([r for r, _ in pairs], weights=[w for _, w in pairs])[0]

    def path(self, rng: random.Random, guard: RelayEntry | None = None,
             distinct_networks: bool = True) -> tuple[RelayEntry, RelayEntry, RelayEntry]:
        """Сначала Exit, затем допустимый Guard и в конце промежуточный узел."""
        if guard is not None:
            guard = next((r for r in self.candidates["guard"]
                          if r.id_rsa == guard.id_rsa), None)
            if guard is None:
                raise LookupError("фиксированный Guard отсутствует среди допустимых узлов консенсуса")
        e = self.choose("exit", [guard] if guard is not None else [], rng, distinct_networks)
        g = guard if guard is not None else self.choose("guard", [e], rng, distinct_networks)
        m = self.choose("middle", [e, g], rng, distinct_networks)
        return g, m, e

def probabilities(consensus: Consensus, position: str) -> dict[str, float]:
    """Распределение без учёта политики выхода и ограничений подсетей."""
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
    """Доля n ретрансляторов с наибольшей вероятностью."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("n должно быть неотрицательным целым числом")
    if any(isinstance(p, bool) or not isinstance(p, (float, int)) or
           not math.isfinite(p) or not 0 <= p <= 1 for p in prob.values()):
        raise ValueError("недопустимая вероятность ретранслятора")
    return sum(sorted(prob.values(), reverse=True)[:n])

@dataclass
class Adversary:
    """Учебная модель независимых цепей, не алгоритм постоянных Guard."""
    guard_share: float
    exit_share: float

    def __post_init__(self) -> None:
        for fraction in (self.guard_share, self.exit_share):
            if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not math.isfinite(fraction) or not 0 <= fraction <= 1:
                raise ValueError("доли противника должны быть конечными числами от 0 до 1")

    def compromised_circuits(self, circuits: int, fixed_guard: bool) -> float:
        """Вероятность, что хотя бы одна цепь содержит Guard и Exit противника."""
        if isinstance(circuits, bool) or not isinstance(circuits, int) or circuits < 0:
            raise ValueError("число цепей должно быть неотрицательным целым числом")
        fraction = self.guard_share * self.exit_share
        if not fixed_guard:
            return 1 - (1 - fraction) ** circuits
        return self.guard_share * (1 - (1 - self.exit_share) ** circuits)
