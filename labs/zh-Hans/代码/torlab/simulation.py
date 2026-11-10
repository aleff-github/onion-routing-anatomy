# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 19：用简化的 TorPS 风格模型模拟首次失守时间。

攻击者控制符合条件的 Guard 与 Exit 各自一定比例的加权带宽。
每位模拟客户端每天建立指定数量的电路；Guard 在教学设定的期限内
保持不变，或对每条电路重新选择。当一条电路同时经过恶意 Guard
与恶意 Exit 时，记为首次失守。不模拟中间中继、Guard 样本优先级、
故障、中继家族、IPv6 及路径之间的依赖。

guard-spec 对未确认 Guard 和已确认 Guard 的默认时限分别为 120
和 60 天；正式算法还维护采样与确认集合，并随机回溯确认日期。
本模型的 48–60 天仅为教学近似，不等于真实 Guard 生命周期
或匿名性预测。
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

GUARD_LIFETIME = 120                  # 未确认 Guard 的默认寿命（天）
GUARD_CONFIRMED_MIN_LIFETIME = 60     # 已确认 Guard 的默认最短寿命（天）
BACKDATE = GUARD_LIFETIME // 10       # 教学模型的最大日期回溯天数


def _positive_int(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} 必须为正整数")


def _guard_lifetime(rng: random.Random, lifetime: int) -> int:
    """近似 Guard 寿命，确保日期回溯后仍为正数。"""
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime < 1:
        raise ValueError("Guard 寿命必须是正整数")
    return lifetime - rng.randint(0, min(BACKDATE, lifetime - 1))


class WeightedUrn:
    """验证带宽权重和攻击者占比的加权抽样器。"""

    def __init__(self, weights: list[float], adversary_share: float):
        if isinstance(adversary_share, bool) or not isinstance(adversary_share, (int, float)) or not math.isfinite(adversary_share) or not 0 <= adversary_share <= 1:
            raise ValueError("攻击者份额必须是 0 到 1 之间的有限数值")
        if any(isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or w < 0 for w in weights):
            raise ValueError("权重必须是有限的非负数")
        self.n = len(weights)
        self.all_adversarial = adversary_share == 1
        if self.all_adversarial:
            self.cumulative = []
            return
        max_weight = max(weights, default=0.0)
        if max_weight <= 0:
            raise ValueError("至少需要一个权重大于零的正常中继")
        scaled = [w / max_weight for w in weights]
        total = math.fsum(scaled)
        if not math.isfinite(total) or total <= 0:
            raise ValueError("至少需要一个权重大于零的正常中继")
        honest = 1.0 - adversary_share
        # 先按最大权重归一化，避免浮点溢出。
        normalized = [w / total * honest for w in scaled]
        self.cumulative = list(itertools.accumulate(normalized + [adversary_share]))

    def adversarial(self, rng: random.Random) -> bool:
        """返回当前抽样是否属于攻击者。"""
        if self.all_adversarial:
            return True
        x = rng.random() * self.cumulative[-1]
        return bisect.bisect_right(self.cumulative, x) >= self.n


@dataclass
class Result:
    """每位模拟客户端的首次失守日；None 代表未观测到事件。"""
    days_to_compromise: list[int | None]

    def fraction_by(self, day: int) -> float:
        """返回截至指定日期失守的客户端比例。"""
        if isinstance(day, bool) or not isinstance(day, int) or day < 0:
            raise ValueError("日期必须是非负整数")
        if not self.days_to_compromise:
            raise ValueError("模拟结果没有客户端")
        return sum(1 for d in self.days_to_compromise if d is not None and d <= day) / len(self.days_to_compromise)

    def median(self) -> int | None:
        """至少半数客户端失守的最早日期。"""
        if not self.days_to_compromise:
            return None
        compromised = sorted(d for d in self.days_to_compromise if d is not None)
        needed = (len(self.days_to_compromise) + 1) // 2
        return compromised[needed - 1] if len(compromised) >= needed else None


def simulate(consensus: Consensus, guard_share: float, exit_share: float, *, client: int = 2000,
           days: int = 180, circuits: int = 20, persistent_guard: bool = True,
           guard_lifetime: int = GUARD_CONFIRMED_MIN_LIFETIME, seed: int = 1) -> Result:
    """蒙特卡洛教学近似，不能预测真实 Tor 去匿名化。"""
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
        raise SystemExit("用法: python -m torlab.simulation 共识文件 [攻击者份额]")
    path = Path(sys.argv[1])
    c = parse_consensus(path.read_text(encoding="utf-8"))
    q = float(sys.argv[2]) if len(sys.argv) > 2 else 0.01
    print(f"攻击者: {q:.0%} Guard 带宽及 {q:.0%} Exit 带宽; 2000 客户端, 180 天, 20 电路/天")
    for persistent in (True, False):
        result = simulate(c, q, q, persistent_guard=persistent)
        summary = "  ".join(f"{d:>3}d: {result.fraction_by(d):5.1%}" for d in (1, 7, 30, 90, 180))
        label = ("持久 Guard" if persistent else "每条电路更换 Guard")
        print(f"{label:19s} {summary}  中位数: {result.median()}")
