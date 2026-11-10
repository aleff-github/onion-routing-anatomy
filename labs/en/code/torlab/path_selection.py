# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratory 7 — path selection.

References: path-spec, "Path selection and constraints" and "Weighting node selection";
dir-spec, "bandwidth-weights". Implements weighted selection of exits, guards, and middles
with the main constraints (flags, distinct relays, same-/16 exclusion). Families, which require
microdescriptors, are left as an exercise.
Teaching module: real tor path selection has many more rules (persistent guards,
vanguards, stream isolation, and port preferences).
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
        raise ValueError("unknown relay position")


def _check_scale(scale: int) -> None:
    if isinstance(scale, bool) or not isinstance(scale, int) or not 1 <= scale <= 2 ** 31 - 1:
        raise ValueError("invalid consensus bwweightscale")


def _relay_type(r: RelayEntry) -> str:
    """g = Guard only, e = Exit only, d = both Guard and Exit, m = neither."""
    g, e = "Guard" in r.flag, "Exit" in r.flag  # BadExit forbids exit use, not Exit bandwidth categorization
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]


def weight(r: RelayEntry, position: str, weights: dict[str, int], scale: int = 10000) -> float:
    """Apply W<position><kind>, divided by the consensus bwweightscale."""
    _check_position(position)
    _check_scale(scale)
    bw = r.bandwidth if r.bandwidth is not None else 0
    if isinstance(bw, bool) or not isinstance(bw, int) or bw < 0:
        raise ValueError("invalid relay bandwidth")
    factor = weights.get(f"W{position[0]}{_relay_type(r)}", scale)
    if isinstance(factor, bool) or not isinstance(factor, int) or not 0 <= factor <= scale:
        raise ValueError("invalid consensus bandwidth weight")
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
    """Validated first two octets of an IPv4 address (/16 prefix)."""
    try:
        ip = ipaddress.IPv4Address(r.ip)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError("invalid relay IPv4 address") from exc
    return ".".join(str(ip).split(".")[:2])

class Selector:
    """Cache eligible weighted relays for each circuit position.

    Constraint-aware sampling is equivalent to repeated rejection draws but
    cannot fail merely because a compatible relay has a tiny weight.
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
        """Select among feasible relays; attempts remains for API compatibility."""
        _check_position(pos)
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
            raise ValueError("attempts must be a positive integer")
        excluded_ids = {r.id_rsa for r in excluded}
        excluded_nets = {network16(r) for r in excluded} if distinct_networks else set()
        pairs = [(r, w) for r, w in zip(self.candidates[pos], self.weights[pos])
                 if r.id_rsa not in excluded_ids
                 and (not distinct_networks or network16(r) not in excluded_nets)]
        if not pairs:
            raise LookupError(f"no eligible relay for position {pos}")
        return rng.choices([r for r, _ in pairs], weights=[w for _, w in pairs])[0]

    def path(self, rng: random.Random, guard: RelayEntry | None = None,
             distinct_networks: bool = True) -> tuple[RelayEntry, RelayEntry, RelayEntry]:
        """Exit first, then a validated guard (if supplied), then the middle."""
        if guard is not None:
            guard = next((r for r in self.candidates["guard"]
                          if r.id_rsa == guard.id_rsa), None)
            if guard is None:
                raise LookupError("fixed guard is not eligible in this consensus")
        e = self.choose("exit", [guard] if guard is not None else [], rng, distinct_networks)
        g = guard if guard is not None else self.choose("guard", [e], rng, distinct_networks)
        m = self.choose("middle", [e, g], rng, distinct_networks)
        return g, m, e

def probabilities(consensus: Consensus, position: str) -> dict[str, float]:
    """Unconstrained weighted probabilities, before exit policies or subnet rules."""
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
    """Share of the n largest probabilities (0 when n is zero)."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("n must be a non-negative integer")
    if any(isinstance(p, bool) or not isinstance(p, (float, int)) or
           not math.isfinite(p) or not 0 <= p <= 1 for p in prob.values()):
        raise ValueError("invalid relay probability")
    return sum(sorted(prob.values(), reverse=True)[:n])

@dataclass
class Adversary:
    """Independent-circuit toy model, not Tor's persistent-guard algorithm."""
    guard_share: float
    exit_share: float

    def __post_init__(self) -> None:
        for fraction in (self.guard_share, self.exit_share):
            if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not math.isfinite(fraction) or not 0 <= fraction <= 1:
                raise ValueError("adversarial shares must be finite fractions in [0,1]")

    def compromised_circuits(self, circuits: int, fixed_guard: bool) -> float:
        """Chance of at least one circuit using an adversarial guard and exit."""
        if isinstance(circuits, bool) or not isinstance(circuits, int) or circuits < 0:
            raise ValueError("circuits must be a non-negative integer")
        fraction = self.guard_share * self.exit_share
        if not fixed_guard:
            return 1 - (1 - fraction) ** circuits
        return self.guard_share * (1 - (1 - self.exit_share) ** circuits)
