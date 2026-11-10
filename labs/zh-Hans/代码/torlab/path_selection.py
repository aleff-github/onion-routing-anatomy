# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 7：路径选择。

规范依据：path-spec 的 Path selection and constraints、Weighting node selection，
以及 dir-spec 的 bandwidth-weights。实现出口、守卫和中间中继的加权选择，
考虑标志、不同中继及 /16 网络互斥等主要约束。需要微描述符的家族约束
作为读者练习保留。正式 tor 还具有持久守卫、Vanguards、流隔离、端口偏好等更多规则。
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
        raise ValueError("未知中继位置")


def _check_scale(scale: int) -> None:
    if isinstance(scale, bool) or not isinstance(scale, int) or not 1 <= scale <= 2 ** 31 - 1:
        raise ValueError("共识 bwweightscale 参数无效")


def _relay_type(r: RelayEntry) -> str:
    """g 仅 Guard，e 仅 Exit，d 同时 Guard 和 Exit，m 两者都不是。"""
    g, e = "Guard" in r.flag, "Exit" in r.flag  # BadExit 禁止作为出口，但不改变带宽权重类别
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]


def weight(r: RelayEntry, position: str, weights: dict[str, int], scale: int = 10000) -> float:
    """使用共识的 bwweightscale 计算 W<位置><类别> 权重。"""
    _check_position(position)
    _check_scale(scale)
    bw = r.bandwidth if r.bandwidth is not None else 0
    if isinstance(bw, bool) or not isinstance(bw, int) or bw < 0:
        raise ValueError("中继带宽无效")
    factor = weights.get(f"W{position[0]}{_relay_type(r)}", scale)
    if isinstance(factor, bool) or not isinstance(factor, int) or not 0 <= factor <= scale:
        raise ValueError("共识带宽权重无效")
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
    """经过验证的 IPv4 地址前两个八位字节（/16 前缀）。"""
    try:
        ip = ipaddress.IPv4Address(r.ip)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError("中继 IPv4 地址无效") from exc
    return ".".join(str(ip).split(".")[:2])

class Selector:
    """按电路位置缓存符合条件的中继与带宽权重。

    在可用候选集合上采样，不会因为某节点权重极低而意外失败。
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
        """从符合条件的中继采样；保留 attempts 参数兼容旧接口。"""
        _check_position(pos)
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
            raise ValueError("尝试次数必须为正整数")
        excluded_ids = {r.id_rsa for r in excluded}
        excluded_nets = {network16(r) for r in excluded} if distinct_networks else set()
        pairs = [(r, w) for r, w in zip(self.candidates[pos], self.weights[pos])
                 if r.id_rsa not in excluded_ids
                 and (not distinct_networks or network16(r) not in excluded_nets)]
        if not pairs:
            raise LookupError(f"该位置没有满足条件的中继 {pos}")
        return rng.choices([r for r, _ in pairs], weights=[w for _, w in pairs])[0]

    def path(self, rng: random.Random, guard: RelayEntry | None = None,
             distinct_networks: bool = True) -> tuple[RelayEntry, RelayEntry, RelayEntry]:
        """先选择 Exit，然后有效 Guard，最后选择中间中继。"""
        if guard is not None:
            guard = next((r for r in self.candidates["guard"]
                          if r.id_rsa == guard.id_rsa), None)
            if guard is None:
                raise LookupError("固定 Guard 不属于当前共识的有效候选")
        e = self.choose("exit", [guard] if guard is not None else [], rng, distinct_networks)
        g = guard if guard is not None else self.choose("guard", [e], rng, distinct_networks)
        m = self.choose("middle", [e, g], rng, distinct_networks)
        return g, m, e

def probabilities(consensus: Consensus, position: str) -> dict[str, float]:
    """不考虑出口策略或子网约束时的带权概率。"""
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
    """最高的 n 个中继概率之和（n=0 时为 0）。"""
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("n 必须为非负整数")
    if any(isinstance(p, bool) or not isinstance(p, (float, int)) or
           not math.isfinite(p) or not 0 <= p <= 1 for p in prob.values()):
        raise ValueError("中继概率无效")
    return sum(sorted(prob.values(), reverse=True)[:n])

@dataclass
class Adversary:
    """独立电路的教学模型，并非 Tor 持久 Guard 算法。"""
    guard_share: float
    exit_share: float

    def __post_init__(self) -> None:
        for fraction in (self.guard_share, self.exit_share):
            if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not math.isfinite(fraction) or not 0 <= fraction <= 1:
                raise ValueError("攻击者份额必须是 0 到 1 之间的有限数值")

    def compromised_circuits(self, circuits: int, fixed_guard: bool) -> float:
        """至少一条电路同时经过攻击者 Guard 和 Exit 的概率。"""
        if isinstance(circuits, bool) or not isinstance(circuits, int) or circuits < 0:
            raise ValueError("电路数量必须为非负整数")
        fraction = self.guard_share * self.exit_share
        if not fixed_guard:
            return 1 - (1 - fraction) ** circuits
        return self.guard_share * (1 - (1 - self.exit_share) ** circuits)
