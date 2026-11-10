# Laboratory 16 — Correlating Your Own Traffic

| | |
|---|---|
| **Chapter** | 26 — Attacks on the Network |
| **Requires network?** | Yes, the book's private network only |
| **Prerequisites** | Running Chutney network with Tor client `008c` |
| **Time** | 1–2 hours to explore; 20-second nominal traffic interval |
| **File** | `labs/en/lab/correlation.py` |

> **Use only self-generated synthetic traffic in the disposable private lab.** Correlation of others' traffic is outside the scope of this experiment.

## What the Experiment Actually Observes

The script opens **six concurrent synthetic TCP streams through one Tor client process**, `008c`, at SOCKS port 9008. It does **not** start six independent Tor clients. Each stream uses different SOCKS username/password credentials to request separate isolation contexts; that **does not guarantee** a fixed distinct circuit for every stream.

The sending-side measurement records timestamps after `sendall`. The receiving-side measurement comes from a **local server controlled by the experiment** at `127.0.0.1:8095`, recording `recv` events. **This is not passive packet capture on the Tor exit relay**: the server is the test destination, and both clocks run on the same computer.

The sender transmits a **four-byte plaintext client identifier** at the beginning of each synthetic stream. The receiver stores it to score the resulting matches, but **the Pearson matching calculation does not use this identifier**. Since the destination can read the label anyway, the lab is **not** a demonstration that unknown users can be identified from timing alone by an otherwise uninformed observer.

## Preparation and Run

From the repository root, build the Docker image before the first use, then start only this language's private network:

```bash
# First run only: make -C labs/en/lab image
make -C labs/en/lab start
docker exec -w /tmp torbook-network python3 /lab/correlation.py 3
```

The argument `3` seeds the pseudo-random generators. It reproduces **random choices**, not exact timestamps, exit-flow ordering or correlation scores: thread scheduling, TCP segmentation, buffering and circuit timing introduce variability. The script uses **250 ms** bins for a nominal **20 seconds** of generated traffic; setup and cleanup add time.

## Example Output (Varies Between Runs)

```text
client 0: +0.24 -0.04 +0.09 +0.86 +0.00 -0.04  -> exit_flow 3 OK
client 2: -0.03 +0.85 +0.35 -0.07 +0.13 -0.05  -> exit_flow 1 OK
client 5: +0.87 -0.01 +0.27 +0.26 +0.05 +0.15  -> exit_flow 0 OK
client 4: +0.09 +0.32 +0.85 -0.07 +0.02 +0.10  -> exit_flow 2 OK
client 1: +0.24 -0.07 +0.19 +0.08 -0.03 +0.72  -> exit_flow 5 OK
client 3: +0.17 +0.13 +0.04 +0.13 +0.70 +0.09  -> exit_flow 4 OK
correct matches: 6/6
```

Each row lists six **Pearson correlation coefficients**, one for each receiver-side flow in flow-ID order, computed from **bytes per time bin**. The receiver assigns arbitrary flow IDs by arrival order. The example coefficients are historical, not a guaranteed range. A constant or missing series cannot provide a meaningful coefficient.

For each input stream, the code independently selects the **highest coefficient**. It does **not** solve a global one-to-one assignment: two input flows could independently select the same receiver-side flow. The original known mapping is consulted only **after** selection to produce `OK` or `WRONG`.

The reference run showed 6/6; 5/6 is also an accepted teaching result. The script checks for all six streams, propagates worker failures, reads complete SOCKS5 replies, rejects invalid correlations and exits with an error if fewer than five matches are correct.

## What This Does Not Demonstrate

A real-world adversary must obtain observations of both ends with adequate clock alignment and data quality. Public-network noise, traffic diversity, jitter, sample size and the chosen classifier substantially affect performance. Six synthetic flows cannot establish the attack's success rate against real Tor users. Persistent guards ([Laboratory 19](Laboratory-19-Simulation.md)) reduce exposure to new entry positions but do not eliminate correlation if both sides are observed.

## Verification and Troubleshooting

The **Italian** `scripts/verify_labs.py::lab16` checks only the last printed line for `5/6` or `6/6`; it **does not check the subprocess return code**, so it is not a full runtime test.

| Symptom | Check |
|---|---|
| Fewer than five matches | The six rhythms may be insufficiently distinct; repeat on the private network and record the seed and network state. |
| Missing flow or SOCKS5 error | Check node `008c`, SOCKS port 9008, SOCKS5 negotiation and the local receiver. |
| No usable time series | The code rejects incomplete or constant series instead of manufacturing a result. |
| `Address already in use` | Another test server is listening on the local port 8095; stop that test instance. |
