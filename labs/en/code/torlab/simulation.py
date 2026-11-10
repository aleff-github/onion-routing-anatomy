# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratory 19 — first compromise in a simplified TorPS-style simulation.

An adversary controls a fixed fraction of eligible guard and exit bandwidth.
Each simulated client builds a fixed number of circuits per day; its guard is
either persistent for a configurable toy lifetime or resampled per circuit.
A client is counted as compromised when one circuit has both a malicious guard
and a malicious exit. Intermediate relays, guard sampling/priority, failures,
relay families, IPv6 and path dependencies are not modeled.

The 120-day unconfirmed and 60-day confirmed guard limits are defaults from
guard-spec; the specification manages sampled/confirmed sets and randomizes
confirmation dates. Our 48–60-day range is ONLY a teaching approximation,
not the real Tor guard-selection lifecycle or an anonymity forecast.
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

GUARD_LIFETIME = 120                  # Unconfirmed guard lifetime default (days)
GUARD_CONFIRMED_MIN_LIFETIME = 60     # Confirmed guard minimum lifetime default (days)
BACKDATE = GUARD_LIFETIME // 10       # Maximum date backdating in the toy model (days)


def _positive_int(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")


def _guard_lifetime(rng: random.Random, lifetime: int) -> int:
    """Approximate a guard's fixed lifetime, clamping backdating to keep it positive."""
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime < 1:
        raise ValueError("guard lifetime must be a positive integer")
    return lifetime - rng.randint(0, min(BACKDATE, lifetime - 1))


class WeightedUrn:
    """Validated weighted sampler with an explicit adversarial bandwidth fraction."""

    def __init__(self, weights: list[float], adversary_share: float):
        if isinstance(adversary_share, bool) or not isinstance(adversary_share, (int, float)) or not math.isfinite(adversary_share) or not 0 <= adversary_share <= 1:
            raise ValueError("adversarial share must be a finite fraction in [0,1]")
        if any(isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or w < 0 for w in weights):
            raise ValueError("weights must be finite nonnegative numbers")
        self.n = len(weights)
        self.all_adversarial = adversary_share == 1
        if self.all_adversarial:
            self.cumulative = []
            return
        max_weight = max(weights, default=0.0)
        if max_weight <= 0:
            raise ValueError("at least one honest relay with positive weight is required")
        scaled = [w / max_weight for w in weights]
        total = math.fsum(scaled)
        if not math.isfinite(total) or total <= 0:
            raise ValueError("at least one honest relay with positive weight is required")
        honest = 1.0 - adversary_share
        # Normalize by the largest weight first to avoid float overflow.
        normalized = [w / total * honest for w in scaled]
        self.cumulative = list(itertools.accumulate(normalized + [adversary_share]))

    def adversarial(self, rng: random.Random) -> bool:
        """Return whether this sample corresponds to the adversary."""
        if self.all_adversarial:
            return True
        x = rng.random() * self.cumulative[-1]
        return bisect.bisect_right(self.cumulative, x) >= self.n


@dataclass
class Result:
    """One first-compromise day per simulated client; None means censored."""
    days_to_compromise: list[int | None]

    def fraction_by(self, day: int) -> float:
        """Fraction of clients compromised on or before the given day."""
        if isinstance(day, bool) or not isinstance(day, int) or day < 0:
            raise ValueError("day must be a nonnegative integer")
        if not self.days_to_compromise:
            raise ValueError("simulation result has no clients")
        return sum(1 for d in self.days_to_compromise if d is not None and d <= day) / len(self.days_to_compromise)

    def median(self) -> int | None:
        """First day on which at least half of all clients are compromised."""
        if not self.days_to_compromise:
            return None
        compromised = sorted(d for d in self.days_to_compromise if d is not None)
        needed = (len(self.days_to_compromise) + 1) // 2
        return compromised[needed - 1] if len(compromised) >= needed else None


def simulate(consensus: Consensus, guard_share: float, exit_share: float, *, client: int = 2000,
           days: int = 180, circuits: int = 20, persistent_guard: bool = True,
           guard_lifetime: int = GUARD_CONFIRMED_MIN_LIFETIME, seed: int = 1) -> Result:
    """Monte Carlo illustration; never a calibrated Tor de-anonymization prediction."""
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
        raise SystemExit("Usage: python -m torlab.simulation CONSENSUS_FILE [ADVERSARY_SHARE]")
    path = Path(sys.argv[1])
    c = parse_consensus(path.read_text(encoding="utf-8"))
    q = float(sys.argv[2]) if len(sys.argv) > 2 else 0.01
    print(f"adversary: {q:.0%} of guard bandwidth and {q:.0%} of exit bandwidth; 2000 clients, 180 days, 20 circuits/day")
    for persistent in (True, False):
        result = simulate(c, q, q, persistent_guard=persistent)
        summary = "  ".join(f"{d:>3}d: {result.fraction_by(d):5.1%}" for d in (1, 7, 30, 90, 180))
        label = ("persistent guard" if persistent else "per-circuit guard")
        print(f"{label:19s} {summary}  median: {result.median()}")
