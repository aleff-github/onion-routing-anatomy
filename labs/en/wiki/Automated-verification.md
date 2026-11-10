# Automated Verification

The English edition has its own source tree under `labs/en/`. **Having scripts and tests there does not establish that the experiments were executed or all claims checked.** Offline Python tests, Chutney network checks and individual live experiments are distinct. Docker uses `--network host` and language editions share port ranges.

## Core Commands

From the repository root (build the image on first use, which needs Internet access):

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test
make -C labs/en/lab image       # first use; fetches Tor, Chutney and dependencies
make -C labs/en/lab start
make -C labs/en/lab verify
make -C labs/en/lab status
```

The first command runs English `torlab` unit and regression tests against stored fixtures, **not Tor or an HTTP server on port 8080**. The suite covers binary formats, official vectors where available, negative cases, parsing and calculations; its count and results must be determined by running it.

The second command starts the private `book` topology. The third runs Chutney's end-to-end verification against the topology that is currently active. The fourth reports node status.

## Code Tests

The English test suite is located in `labs/en/code/torlab/test/`. It does not require the public Tor network.

Important categories include:

- **Protocol-format tests** for cells, channels, directory documents, and relay messages.
- **Cryptographic vectors**, including Proposal 332 for ntor-v3 and Proposal 216 for ntor HKDF.
- **Negative tests** for modified signatures, invalid authentication values, expired certificates, malformed lengths, and mismatched identities.
- **Reproducibility tests** for calculations used in the book.

A successful positive-path test alone is not sufficient. A verifier that accepts every input would also pass a positive test, which is why the suite includes deliberate failures.

## Private-Network Verification

After building the image on first use, start the standard English topology **only if another language's network is not occupying the shared host ports**:

```bash
make -C labs/en/lab start
make -C labs/en/lab verify
```

The `verify` target invokes Chutney against the active topology and checks end-to-end delivery. Laboratory-specific scripts under `labs/en/lab/` run separately. **They can change disposable node configurations or open local services and are not invoked by `make -C labs/en/lab verify`.** Read the relevant laboratory guide and confirm the `book` topology is active; never target public relays.

Examples:

```bash
PYTHONPATH=labs/en/code python3 labs/en/lab/exit_policy.py
PYTHONPATH=labs/en/code python3 labs/en/lab/restricted_discovery.py
PYTHONPATH=labs/en/code python3 labs/en/lab/relay_early.py 8 9
```

## Bridge Topology

Laboratory 10 uses `book-bridge`, which is separate from the ordinary `book` topology:

```bash
make -C labs/en/lab clean
make -C labs/en/lab start NETWORK=book-bridge
make -C labs/en/lab verify
```

When finished:

```bash
make -C labs/en/lab clean
make -C labs/en/lab start
```

The `verify` target does not switch topologies by itself. **Both `clean` commands delete `labs/en/lab/net/` completely**, including keys and onion-service identities. The bridge topology has 12 nodes and no standard `009h` onion-service node. Confirm all saved state is disposable.

## Interpreting Failures

| Symptom | Likely explanation |
|---|---|
| A network experiment fails once and succeeds on retry | Preserve the logs and investigate: passing on retry alone is not proof of correctness. |
| The same step fails consistently | Treat it as a real regression until the cause is understood. |
| Every network experiment fails | Check `make -C labs/en/lab status` and the authority logs under `labs/en/lab/net/nodes/`. |
| A cryptographic negative test unexpectedly succeeds | Stop and investigate: a verifier may be accepting invalid input. |
| Public-snapshot calculations differ | Confirm that the same archived consensus and reference date are being used. |

## Before Publishing a Release

Run at least:

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test
make -C labs/en/lab start
make -C labs/en/lab verify
```

Then rerun each laboratory script whose output is quoted in the book and inspect **exit codes, logs, cleanup and observations**, not merely printed values. Neither pytest nor Chutney `verify` alone certifies all twenty laboratories. Recorded values that depend on timing, fresh onion-service keys, consensus state, or packet capture will legitimately differ between runs; protocol structure and stated invariants must still match.

English commands should stay within `labs/en/`. The Italian `labs/it/codice/`, `labs/it/laboratorio/` and the root `scripts/` belong to the Italian edition, **not English execution paths**. Italian `make verifica-lab` and `make verifica-lab-bridge` do not certify the English edition.
