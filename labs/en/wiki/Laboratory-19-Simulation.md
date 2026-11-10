# Laboratory 19 — Time to First Compromise

| | |
|---|---|
| **Chapter** | 29 — Research on Tor |
| **Requires network?** | No Tor connection during simulation; HTTPS is needed to download the historical consensus if absent |
| **Prerequisites** | Laboratories 7 and 15 |
| **Time** | 1–2 hours to implement; runtime depends on the machine |
| **File** | `labs/en/code/torlab/simulation.py` |

## What This Demonstrates

This laboratory isolates the effect of persistent guards in an intentionally simplified, offline model. In the source simulation, an adversary controlling 5% of weighted guard bandwidth and 5% of weighted exit bandwidth compromises **half the clients within fifteen days** if a fresh guard is chosen for each circuit, and almost all within three months. With persistent guards, 18.4% are compromised after six months.

Persistent guards do not reduce the average per-circuit probability in a simple model; they **concentrate** exposure. Most clients keep an honest guard and face little entry-side exposure in the simulated window, while clients that selected a malicious guard remain exposed.

## Preparation

As in [Laboratory 7](Laboratory-07-Path-selection.md), first run `make -C labs/en data` to obtain the public archive (not included in Git), then use the consensus at `labs/en/data/collector/consensus-microdesc-2026-09-23-15`.

## Run the Experiment

```bash
export PYTHONPATH=labs/en/code
python3 -m torlab.simulation labs/en/data/collector/consensus-microdesc-2026-09-23-15 0.05
```

The second argument is the adversary's bandwidth share, here 5%.

## Reference Output

The numbers below refer to the specified September 2026 consensus. They must not be presented as measured rates for real Tor users.

```
adversary: 5% of guard bandwidth and 5% of exit bandwidth; 2000 clients, 180 days, 20 circuits/day
persistent guard     1d:  2.6%    7d:  4.4%   30d:  4.4%   90d:  9.4%  180d: 18.4%  median: None
per-circuit guard    1d:  4.3%    7d: 27.9%   30d: 76.5%   90d: 98.9%  180d: 100.0%  median: 15
```

The simulation is **deterministic** because the module fixes its random seed. Running it twice against the same consensus produces the same results. If the values differ, first check whether the consensus file differs.

How to interpret it:

- **Persistent-guard row.** Compromise rises quickly among clients that initially selected the malicious guard, then remains nearly flat until guard rotation. New compromise opportunities appear around each rotation interval. The simulation replaces its single selected guard after an approximate **48–60-day confirmed-guard interval**. Real Tor clients maintain sampled and confirmed guard sets, have reachability rules, and can use several guards; the simplified periodic replacement is **not an implementation of the complete Tor guard-selection algorithm**. The default `GUARD_CONFIRMED_MIN_LIFETIME` is 60 days, while `GUARD_LIFETIME` defaults to 120 days for unconfirmed sampled guards; Tor's network parameters can override these defaults.
- **New guard per circuit.** Every circuit becomes a fresh chance to select both an adversarial guard and exit, so opportunities accumulate rapidly. Median time to first compromise is 15 days in this source run.
- `median: None` on the persistent-guard row means fewer than half of simulated clients were compromised within the 180-day observation window; the median therefore lies outside the simulated interval.

The source also records:

| Adversary share | Compromised after 180 days, persistent guards | No persistent guards |
|---:|---:|---:|
| 1% | 3.9% | 30.9% |
| 5% | 18.4% | 100.0% |

## The Model and Its Limits

The model contains 2,000 clients, 180 days, and 20 circuits per client per day. A client becomes compromised the first day a circuit contains **both** the adversary's guard and the adversary's exit.

It deliberately omits middle relays, relay families, /16 constraints, fallback guards, connection failures, AS-level routing, and many production details. Its purpose is to isolate one mechanism rather than forecast real-world deanonymization rates.

For speed, relay sampling uses binary search over cumulative weights instead of repeatedly invoking `random.choices` across thousands of relays.

## Automated Verification

The Italian reference verifier `scripts/verify_labs.py::lab19` checks the Italian simulation and the archived consensus against two headline values; it does **not** automatically certify this English module or guide: 18.4% after six months with persistent guards, and 100% with median 15 days when selecting a new guard for every circuit.

## Known Problems

The archived consensus is **not included in Git**. Prepare it with `make -C labs/en data` (HTTPS download) before running the simulation. The exact historical percentages have **not** been revalidated here against the public snapshot. The Python simulation itself uses the standard library and local `torlab` modules; no running Tor/Chutney instance is needed.

## Where to Go Next

- Chapter 13 explains confirmed-guard lifetime and the distinction between `GUARD_LIFETIME` and `GUARD_CONFIRMED_MIN_LIFETIME`.
- Chapter 26 discusses the traffic-correlation attack modeled here, while [Laboratory 16](Laboratory-16-Correlation.md) demonstrates correlation using only traffic generated by the experiment itself.
