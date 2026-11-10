# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 19 — время первой компрометации в упрощённой модели TorPS.

Противник контролирует фиксированные доли взвешенной полосы Guard и Exit.
Каждый клиент создаёт заданное число цепей в день: сохраняет Guard в течение
условного срока либо выбирает новый Guard на каждую цепь. Компрометация
наступает, когда одна цепь содержит Guard и Exit противника.
Промежуточные узлы, выбор и приоритет Guard, сбои, семейства,
IPv6 и зависимости маршрутов здесь не моделируются.

В guard-spec сроки по умолчанию составляют 120 дней для неподтверждённых
Guard и 60 дней для подтверждённых; реальные списки и даты подтверждения
имеют дополнительные правила. Диапазон 48–60 дней — только учебное
приближение, а не точный срок использования Guard или прогноз анонимности.
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

GUARD_LIFETIME = 120                  # Обычный срок неподтверждённого Guard (дни)
GUARD_CONFIRMED_MIN_LIFETIME = 60     # Минимальный срок подтверждённого Guard (дни)
BACKDATE = GUARD_LIFETIME // 10       # Максимальный сдвиг даты назад в учебной модели


def _positive_int(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} должно быть положительным целым числом")


def _guard_lifetime(rng: random.Random, lifetime: int) -> int:
    """Приближённый срок Guard; ретродатирование не делает его неположительным."""
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime < 1:
        raise ValueError("срок Guard должен быть положительным целым")
    return lifetime - rng.randint(0, min(BACKDATE, lifetime - 1))


class WeightedUrn:
    """Проверяемый взвешенный выбор с явной долей полосы противника."""

    def __init__(self, weights: list[float], adversary_share: float):
        if isinstance(adversary_share, bool) or not isinstance(adversary_share, (int, float)) or not math.isfinite(adversary_share) or not 0 <= adversary_share <= 1:
            raise ValueError("доля противника должна быть конечным числом от 0 до 1")
        if any(isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or w < 0 for w in weights):
            raise ValueError("веса должны быть конечными неотрицательными числами")
        self.n = len(weights)
        self.all_adversarial = adversary_share == 1
        if self.all_adversarial:
            self.cumulative = []
            return
        max_weight = max(weights, default=0.0)
        if max_weight <= 0:
            raise ValueError("требуется хотя бы один честный узел с положительным весом")
        scaled = [w / max_weight for w in weights]
        total = math.fsum(scaled)
        if not math.isfinite(total) or total <= 0:
            raise ValueError("требуется хотя бы один честный узел с положительным весом")
        honest = 1.0 - adversary_share
        # Нормируем по максимальному весу, чтобы избежать переполнения float.
        normalized = [w / total * honest for w in scaled]
        self.cumulative = list(itertools.accumulate(normalized + [adversary_share]))

    def adversarial(self, rng: random.Random) -> bool:
        """Определяет, принадлежит ли выбранная доля противнику."""
        if self.all_adversarial:
            return True
        x = rng.random() * self.cumulative[-1]
        return bisect.bisect_right(self.cumulative, x) >= self.n


@dataclass
class Result:
    """День первой компрометации для каждого клиента, None означает цензуру."""
    days_to_compromise: list[int | None]

    def fraction_by(self, day: int) -> float:
        """Доля клиентов, скомпрометированных не позднее данного дня."""
        if isinstance(day, bool) or not isinstance(day, int) or day < 0:
            raise ValueError("день должен быть неотрицательным целым")
        if not self.days_to_compromise:
            raise ValueError("в результате моделирования нет клиентов")
        return sum(1 for d in self.days_to_compromise if d is not None and d <= day) / len(self.days_to_compromise)

    def median(self) -> int | None:
        """Первый день, когда скомпрометировано не менее половины всех клиентов."""
        if not self.days_to_compromise:
            return None
        compromised = sorted(d for d in self.days_to_compromise if d is not None)
        needed = (len(self.days_to_compromise) + 1) // 2
        return compromised[needed - 1] if len(compromised) >= needed else None


def simulate(consensus: Consensus, guard_share: float, exit_share: float, *, client: int = 2000,
           days: int = 180, circuits: int = 20, persistent_guard: bool = True,
           guard_lifetime: int = GUARD_CONFIRMED_MIN_LIFETIME, seed: int = 1) -> Result:
    """Учебная модель Монте-Карло, не прогноз деанонимизации реального Tor."""
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
        raise SystemExit("Использование: python -m torlab.simulation ФАЙЛ_КОНСЕНСУСА [ДОЛЯ_ПРОТИВНИКА]")
    path = Path(sys.argv[1])
    c = parse_consensus(path.read_text(encoding="utf-8"))
    q = float(sys.argv[2]) if len(sys.argv) > 2 else 0.01
    print(f"противник: {q:.0%} полосы Guard и {q:.0%} полосы Exit; 2000 клиентов, 180 дней, 20 цепей/день")
    for persistent in (True, False):
        result = simulate(c, q, q, persistent_guard=persistent)
        summary = "  ".join(f"{d:>3}d: {result.fraction_by(d):5.1%}" for d in (1, 7, 30, 90, 180))
        label = ("постоянный Guard" if persistent else "Guard на цепь")
        print(f"{label:19s} {summary}  медиана: {result.median()}")
