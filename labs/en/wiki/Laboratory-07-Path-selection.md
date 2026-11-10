# Laboratory 7 — Bandwidth-Weighted Path Selection

| | |
|---|---|
| **Chapter** | 13 — Path Selection |
| **Requires network?** | No; uses a real consensus saved on disk |
| **Prerequisites** | Laboratory 6 (`directory.py`) |
| **Time** | About 2 hours to implement; about one minute to rerun |
| **File** | `labs/en/code/torlab/path_selection.py` |

## What This Demonstrates

**Scope:** this is a simplified statistical model, **not the production Tor path-selection algorithm**. It omits relay families, destination-specific exit policies, persistent-guard filtering, IPv6 subnet restrictions, and some configuration-dependent exceptions. Reported probabilities for each position are *unconditional candidate-weight shares*, not the actual probabilities after exclusions and rejection sampling.

Choosing the three relays in a Tor circuit is not naïve randomness. Each relay is sampled with probability proportional to its bandwidth, adjusted by a weight that depends on the relay's type—guard, exit, both, or neither—and its position in the circuit. Selection constraints apply on top of those probabilities: three distinct relays, three distinct /16 networks, a guard in the first position, and an exit in the third.

This laboratory uses a **public consensus**, not the ten-node private network, because the private network is too small to demonstrate meaningful network-wide proportions.

## Preparation

The repository does not ship the 2026-09-23 public snapshot. From the repository root run `make -C labs/en data`: this calls the localized `fetch-public-data.sh` to extract the exact microdescriptor consensus from the September 2026 CollecTor archive. It requires network access during preparation only and keeps the data in `labs/en/data/collector/`. The older one-file URL under `/recent/` is not a permanent archive link.

```bash
make -C labs/en data
export PYTHONPATH=labs/en/code
```

The sample output below is conditional on using the exact archived consensus; it has not been rerun here.

## Run the Experiment

```bash
export PYTHONPATH=labs/en/code
python3 - <<'EOF'
import random
from collections import Counter
from torlab.directory import parse_consensus
from torlab.path_selection import Selector, probabilities, top_share, _relay_type, network16
from torlab.metrics import summary

c = parse_consensus(open("labs/en/data/collector/consensus-microdesc-2026-09-23-15").read())
r = summary(c)
print(f"relay: {r['relay']}")
print(f"bandwidth with Guard: {100*r['guard_bandwidth_share']:.1f}%    "
      f"bandwidth with Exit: {100*r['exit_bandwidth_share']:.1f}%")

for pos in ("guard", "middle", "exit"):
    p = probabilities(c, pos)
    print(f"{pos:<6}: eligible {len(p):>5}; "
          f"top 10 = {100*top_share(p, 10):.1f}%; top 100 = {100*top_share(p, 100):.1f}%")

sel, rng = Selector(c), random.Random(7)          # fixed seed: reproducible results
g, m, e = sel.path(rng)
# Check the normal, internally selected path
assert len({x.id_rsa for x in (g, m, e)}) == 3
assert len({network16(x) for x in (g, m, e)}) == 3
assert "Guard" in g.flag and "Exit" in e.flag and "BadExit" not in e.flag
for name, x in (("guard", g), ("middle", m), ("exit", e)):
    print(f"{name:<6} {x.name:<20} {x.ip:<16} /16 {network16(x):<8} bandwidth {x.bandwidth}")

types = Counter("".join(_relay_type(x) for x in sel.path(rng)) for _ in range(20000))
print("20000 paths:", "  ".join(f"{k} {100*v/20000:.1f}%" for k, v in types.most_common()))
EOF
```

## Expected Output

**Do not use this RNG for real circuits:** `random.Random(7)` is a predictable, deliberately seeded statistical simulation. The teaching selector must not be mistaken for a production Tor client's cryptographically suitable path-selection randomness.

The sample numbers come from one historical consensus and one seeded simulation; `random.Random(7)` reproduces a run only when the input document and code are identical. Timing and network statistics are not constant.

Zero-weight nodes are excluded from `Selector`'s candidate tables. `probabilities()`, however, still counts zero-weight *eligible* relays in the returned dictionary; its `eligible` count is not necessarily the number of relays with non-zero selection probability.

```
relay: 9358
bandwidth with Guard: 70.1%    bandwidth with Exit: 33.1%
guard : eligible  5306; top 10 = 1.7%; top 100 = 12.6%
middle: eligible  8961; top 10 = 2.8%; top 100 = 13.7%
exit  : eligible  3126; top 10 = 2.3%; top 100 = 13.7%
20000 paths: gge 30.9%  ggd 29.4%  gme 20.4%  gmd 19.3%
```

The omitted single-path line will show a particular set of relays; what matters is that all three relays and their /16 networks are distinct.

How to interpret the result:

- The final abbreviations identify relay types: `g` means guard, `e` exit-only, `d` dual guard-and-exit, and `m` neither. `gge`, for example, means a guard first, a relay carrying the Guard flag in the middle, and an exit-only relay last.
- No path uses an exit-flagged relay in the first or middle position in this snapshot because the corresponding consensus weights are zero. Exit capacity is treated as scarce and reserved for where it is needed.
- In a large share of sampled paths, the middle relay also carries the Guard flag because guards contribute a large portion of network capacity and need not be avoided as middles.
- Concentration is modest in the source snapshot: the ten most probable exits represent only a small fraction of total exit selection probability. A network dominated by a handful of relays would be substantially easier to attack.

**The random seed matters.** The final line is a sample. Fixing `random.Random(7)` makes it reproducible; changing the seed changes percentages slightly. Without a fixed seed, comparisons between runs become unnecessarily noisy.

## Automated Verification

The Italian `lab7` checks 500 paths on a real saved public consensus. The localized unit tests in `labs/en/code/torlab/test/test_path_selection.py` instead use the eight-node private-network fixture and deliberately set `distinct_networks=False` for valid three-hop paths; they cannot prove public-network /16 diversity.

For the illustrative default call, check the selected nodes by their RSA identities and their IPv4 /16 prefixes. Do not use nicknames as unique keys.

The `lab7` check builds 500 paths and verifies four invariants: three distinct relay identities, three distinct /16 networks, a guard first, and an exit last.

One subtle point already caused a bug in the original checker: **nicknames are not unique** on the public network. In the source snapshot, 151 nicknames were shared by multiple relays. Compare relays by identity, never by nickname.

## Known Problems

- `FileNotFoundError` for the consensus: see *Preparation*.
- Constructing 20,000 paths took about seven seconds in the source environment. If it takes hundreds of seconds, you may be recomputing relay weights on every draw instead of precomputing them once.

## Where to Go Next

- [Laboratory 15 — Consensus Statistics](Laboratory-15-Metrics.md) uses the same snapshot.
- [Laboratory 19 — Time to First Compromise](Laboratory-19-Simulation.md) reuses this selector to simulate six months of client behavior.

---

# Implementation, in Detail

`labs/en/code/torlab/path_selection.py` is roughly 105 lines and translates two specification areas into code: path-selection constraints from path-spec and bandwidth weights from dir-spec.

## Relay Type

```python
def _relay_type(r: RelayEntry) -> str:
    """g = Guard only, e = Exit only, d = both Guard and Exit, m = neither."""
    g, e = "Guard" in r.flag, "Exit" in r.flag and "BadExit" not in r.flag
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]
```

`BadExit` is part of the **definition** of a usable exit. A relay can carry the `Exit` flag while authorities mark it `BadExit`; it must then be excluded from exit selection. Forgetting this would deliberately route traffic through relays the authorities identified as unsuitable.

The letters match the internal classification used in the module: `d` for a dual guard-and-exit relay, `g` guard-only, `e` exit-only, and `m` middle-only/neither.

## Weight Calculation

```python
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
```

The weight key is **constructed**, not selected through a long `if` chain: the first letter represents circuit position and the second the relay type. `Wmg` therefore means “the weight applied to a guard-capable relay when selecting a middle.”

Several details matter:

- A relay lacking a bandwidth value receives zero selection weight; a negative or non-integer bandwidth is a consensus error.
- The default `scale` means full weight when a particular key is absent.
- Dividing by `scale` converts the consensus's integer weights into a factor between 0 and 1. The scale is the consensus parameter `bwweightscale` (default 10000), which `Selector` reads from the consensus parameters.

In the 23 September 2026 snapshot, the relevant middle/guard weights for exit-capable relays are zero, which is why exit bandwidth is not consumed in positions where it is unnecessary.

## Why Weights Are Computed Once

Zero-weight nodes are excluded from `Selector`'s candidate tables. `probabilities()`, however, still counts zero-weight *eligible* relays in the returned dictionary; its `eligible` count is not necessarily the number of relays with non-zero selection probability.

```python
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
```

An early implementation filtered more than nine thousand relays and recalculated their weights **for every draw**. It took roughly 310 seconds for 2,000 paths. Precomputing candidate lists and weights reduced the same class of workload enough to make repeated simulation practical.

Relays with zero effective weight are removed immediately. Keeping them would only create useless draws that must be discarded.

## Constraints by Rejection Sampling

Two relays count as the same relay when they have the same RSA identity, not when they are the same Python object.

The `/16` test is an IPv4-only teaching approximation. The actual subnet rule is configurable and also covers IPv6 (typically `/32`), with specified exceptions for some onion-service circuits.

```python
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
```

Constraints are enforced by **drawing and rejecting** unsuitable relays rather than rebuilding the entire candidate list before each choice. On a large network, invalid draws are uncommon, so this is much cheaper than repeatedly filtering thousands of entries.

Attempts are capped at 1,000 because, on a tiny network, rejection could go on for a long time: if almost every candidate is in the same /16, valid draws are rare. Once the attempts run out, `choose` filters the compatible relays and picks among them; if none is left, it raises a clear exception instead of hanging.

> **Nicknames are not unique.** In the public source snapshot, 151 nicknames were shared. Comparing relay names instead of identities can silently corrupt path constraints.

## Selection Order

```python
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
```

The code chooses the **exit first**, then the guard, then the middle. This order is deliberate: the exit is usually the most constrained position because it must support the destination. Choosing it last would increase the chance that earlier choices leave no compatible exit and force a restart.

The optional `guard` argument allows callers to pin the first hop. [Laboratory 19](Laboratory-19-Simulation.md) uses this mechanism to model persistent guards. A pinned guard is first looked up among the consensus's eligible candidates (`LookupError` if absent), and the exit is then chosen excluding it by identity and /16 network, so the constraints hold in this case too.

## What This Model Deliberately Omits

**Scope:** this is a simplified statistical model, **not the production Tor path-selection algorithm**. It omits relay families, destination-specific exit policies, persistent-guard filtering, IPv6 subnet restrictions, and some configuration-dependent exceptions. Reported probabilities for each position are *unconditional candidate-weight shares*, not the actual probabilities after exclusions and rejection sampling.

The module implements the major constraints, not the entire production path-selection system. It deliberately omits:

- relay **families**, which require microdescriptor data and are left as a book exercise;
- persistent guard samples with filtered, confirmed, and primary guards;
- onion-service vanguards;
- stream isolation and port preferences.

A model including every production detail would be more realistic but much harder to reason about. The teaching code instead keeps the causal relationship between rules and outcomes visible.

## Where These Rules Come From

| In the code | In the specification |
|---|---|
| Selection constraints | path-spec, *Path selection and constraints* |
| Positional weights | path-spec, *Weighting node selection* |
| `W**` values | dir-spec, *Computing Bandwidth Weights* |
| Relay flags | dir-spec, *Assigning flags in a vote* |
