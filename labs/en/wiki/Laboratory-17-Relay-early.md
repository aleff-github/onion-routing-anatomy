# Laboratory 17 — The RELAY_EARLY Cell Limit

| | |
|---|---|
| **Chapter** | 27 — Real Cases: When the Network Was Attacked |
| **Requires network?** | Yes, only the book's private Chutney network |
| **Prerequisites** | Laboratories 1–4, Docker and the running private network |
| **Time** | About one hour |
| **File** | `labs/en/lab/relay_early.py` |

## Aim and Scope

The [Tor specification](https://spec.torproject.org/tor-spec/relay-early.html) defines an allowance of **eight** outbound `RELAY_EARLY` cells per circuit. A relay receiving **more than eight** on an outbound circuit **SHOULD** close it. **SHOULD is not MUST**: the protocol does not guarantee a particular `DESTROY` reason or a unique outcome in every implementation. A node receiving an **inbound** `RELAY_EARLY` cell, towards the client, **MUST** close the circuit immediately.

The historical direction matters. In **2014**, colluding malicious HSDir and guard relays used the visible outer type distinction `RELAY` versus `RELAY_EARLY` to send a covert tag **toward the client**, linking the client's IP address to a **hidden-service descriptor request**. This did **not** establish that an application page was visited. The outbound limit preceded the attack; the inbound protection was tightened in 2014.

**Crucial experiment limitation:** the script creates a **one-hop circuit to private relay `004r`** and injects deliberately crafted encrypted **`DROP`** relay messages in `RELAY_EARLY` cells. Under the current Tor specification, **clients MUST only put `EXTEND`/`EXTEND2` into `RELAY_EARLY`**, not `DROP`. This probe is therefore **intentionally non-conforming**. Its historical output is not a comprehensive conformance test and may differ between implementations.

## Preparation

Run from the repository root. Build the image on the first use and start only this edition's private network; editions may compete for host ports.

```bash
# First use only: make -C labs/en/lab image
make -C labs/en/lab start
export PYTHONPATH=labs/en/code
```

## Run the Experiment

```bash
python3 labs/en/lab/relay_early.py 8 9
```

The arguments request **separate fresh circuits** for 8 and 9 test cells. The script accepts **only** these two values, refuses duplicates, closes its channel in `finally` and exits nonzero if the historical result is not reproduced. After injecting `DROP` cells (which are not application requests), it tries `BEGIN_DIR` to observe whether the circuit can still establish a directory stream.

## Example Output (Varies Between Runs)

```text
8 cells RELAY_EARLY -> CONNECTED
9 cells RELAY_EARLY -> circuit destroyed, reason 1
```

- With **eight**, the historical `BEGIN_DIR` probe returned `CONNECTED`; this does **not** prove that eight `DROP` messages inside `RELAY_EARLY` must always be accepted.
- With **nine**, the historical `DESTROY` reason **1** was `PROTOCOL`. The specification says a relay **SHOULD** close the circuit after exceeding the limit, not that every relay must send reason 1. Other errors or early termination leave this specific probe inconclusive.
- The allowance is **per circuit**. Extensions may consume it, but this lab uses an **initial one-hop `CREATE2` circuit** to avoid spending cells on multihop extensions. Do not extrapolate an eight-cell *additional* allowance to arbitrary three-hop circuits.

The lab **does not recreate the 2014 inbound signaling attack**; it tests outbound cell counts only. A malicious relay on a circuit may see the outer cell type, but an arbitrary passive observer of link-encrypted TLS traffic cannot simply read it.

## Verification and Troubleshooting

The **Italian** `scripts/verify_labs.py::lab17` checks two **exact output lines** but not the subprocess return code; it can falsely fail when Tor behaves differently without violating a `SHOULD` requirement. The example itself exits with an error if those two historical strings are not reproduced.

| Symptom | Check |
|---|---|
| The 8-cell attempt fails | `DROP` inside `RELAY_EARLY` is a deliberately nonstandard client behavior. Check Tor version and private relay logs before blaming the counter. |
| The 9-cell attempt lacks reason 1 | The spec says **SHOULD close**, but does not mandate that precise code. Record the actual behavior. |
| `CircuitError` during construction | Confirm private `004r` and Chutney bootstrap; do not direct the probe at public relays. |

References: [Tor Specification — RELAY_EARLY](https://spec.torproject.org/tor-spec/relay-early.html); [Tor Project 2014 security advisory](https://blog.torproject.org/tor-security-advisory-relay-early-traffic-confirmation-attack/).
