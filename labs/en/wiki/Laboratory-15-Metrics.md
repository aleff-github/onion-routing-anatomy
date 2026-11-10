# Laboratory 15 — Network Statistics from a Consensus

| | |
|---|---|
| **Chapter** | 24 — Measuring the Network: Tor Metrics |
| **Requires network?** | No for calculations; yes to download the archived source data initially |
| **Prerequisites** | Laboratories 6 and 7 |
| **Time** | About 1 hour to implement; about one minute to rerun |
| **File** | `labs/en/code/torlab/metrics.py` |

## What This Demonstrates

**Some** statistics published by [Tor Metrics](https://metrics.torproject.org/)—such as relay counts, flags and consensus bandwidth weights—can be reconstructed from a public consensus. **User numbers cannot be derived from the consensus alone.** Their estimate additionally requires aggregated directory-request data from relay *extra-info descriptors*, a coverage fraction, and an assumed request rate. This is an estimate of **average daily client presence**, not the number of distinct people.

## Preparation

As in [Laboratory 7](Laboratory-07-Path-selection.md), this laboratory uses an archived consensus that is **not committed to Git**. From the repository root, download the exact historical snapshot before running the analysis:

```bash
make -C labs/en data
```

This prepares `labs/en/data/collector/consensus-microdesc-2026-09-23-15` from the September 2026 CollecTor archive. Check the document identity and date; different snapshots give different figures.

Signature verification additionally requires **authority signing certificates matching September 23, 2026**. The following historical command fetches a *recent* certificate resource, **which need not contain the right historical keys**:

```bash
curl -o labs/en/data/collector/certs 'https://collector.torproject.org/recent/relay-descriptors/certs'
```

Check that the response is not HTML or an error page. A raw certificate document begins with `dir-key-certificate-version 3`; CollecTor-annotated documents may instead begin with an `@type ...` line. **Use a date-compatible archived certificate set** rather than treating a download of current keys as proof that old consensus signatures are invalid.

## Run the Experiment

The module exposes a command-line interface:

```bash
export PYTHONPATH=labs/en/code
python3 -m torlab.metrics labs/en/data/collector/consensus-microdesc-2026-09-23-15
```

## Reference Output

```
relay: 9358
flag: {'Running': 9358, 'Valid': 9358, 'Fast': 8961, 'Stable': 8199, 'V2Dir': 7674,
       'Guard': 5306, 'HSDir': 4050, 'Exit': 3177, 'BadExit': 32, 'MiddleOnly': 28,
       'StaleDesc': 21, 'Authority': 10}
total_bandwidth: 198927900
exit_bandwidth_share: 0.3308947161257923
guard_bandwidth_share: 0.7010271560701139
versions: [('Tor 0.4.9.12', 6027), ('Tor 0.4.9.11', 2520), ('Tor 0.4.9.9', 269), ...]
networks16: [('64.65', 771), ('192.42', 636), ('204.8', 598), ...]
```

How to interpret it:

- In this snapshot, the `Exit` **flag count** is 3,177, while `exit_bandwidth_share` sums only relays with `Exit` **and without `BadExit`**. The roughly 33% and 70% shares are **fractions of the sum of `Bandwidth=` values in this consensus**, *not* observed traffic shares or final circuit-selection probabilities. Guard and exit classes overlap; position-specific bandwidth weights are separate ([Laboratory 7](Laboratory-07-Path-selection.md)).
- The historical snapshot has **ten** relay entries marked `Authority`, whereas signature verification uses **nine** voting-authority identities. The relay flag is **not an authenticated list of signers**. Identifying the extra relay as a bridge authority requires cross-checking the historical identities and documents; the numerical difference alone does not establish it.
- `BadExit` and `MiddleOnly` constrain relay roles according to directory-authority decisions; **neither flag alone proves abuse or compromise**.
- Some IPv4 **/16 prefixes** contain hundreds of relays in this snapshot, but this indicates address concentration, **not proof of a common operator** or that all are exits. /16 separation is one among several path-selection constraints.

Counts are sorted by value and then by name when values tie. Without deterministic tie-breaking, Python's set iteration could make printed ordering vary between runs even when the underlying numbers are unchanged.

## Estimating Users

```bash
python3 - <<'EOF'
from torlab.metrics import estimate_users, remove_rounding
print(estimate_users(20_000_000, 0.6))     # hypothetical: 20 M reported requests; coverage=60%
EOF
```

```
3333333
```

This calculation is an **illustrative input**, `floor(20_000_000 / 0.6 / 10) = 3_333_333`; the module does **not** extract twenty million requests from the consensus. Tor Metrics derives reported request totals from relay *extra-info* statistics, adjusts by an estimated reporting fraction (`frac`), and assumes **10 directory requests per average client-day**. `estimate_users` returns `None` for `frac < 0.10` or `frac > 1.10`; the upper limit deliberately permits slight overcoverage. This estimates average presence, **not unique users**. Counts are privacy-rounded; the separate `remove_rounding` function is **not automatically applied** to the provided example.

## Verifying Signatures

```bash
python3 - <<'EOF'
from torlab.directory import parse_consensus, parse_certificates, verify_consensus
c = parse_consensus(open("labs/en/data/collector/consensus-microdesc-2026-09-23-15").read())
cert = parse_certificates(open("labs/en/data/collector/certs").read())
print(verify_consensus(c, cert, 9)[:2])
EOF
```

```
(9, 5)
```

The reference output is `(9, 5)`: nine recognized valid signatures and a threshold of five. The public files are not stored in the repository; download them first with `make -C labs/en data`. If you obtain `(0, 5)`, investigate HTML downloads, **historically mismatched signing certificates**, the CollecTor `@type ...` annotation, and signed-document byte boundaries. The annotation is metadata, not part of the signed consensus.

## Automated Verification

The **Italian** `scripts/verify_labs.py::lab15` checks snapshot-specific relay counts and bandwidth fractions, the arithmetic of a **hypothetical** user estimate and, if a certificate file is present, the archived consensus signatures. It is not a standalone test of current Tor Metrics user statistics.

## Known Problems

- `valid signatures: (0, 5)`: inspect document boundaries, CollecTor `@type` metadata, HTML error pages **and the historical signing-key validity periods**.
- Using a different consensus changes all snapshot-specific numbers. Failing those exact numerical checks is expected unless the same 23 September 2026 source document is used.
