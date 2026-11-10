# Laboratory 14 — Testing an Exit Policy

| | |
|---|---|
| **Chapter** | 22 — Running a Relay |
| **Requires network?** | Yes, the book's private network only |
| **Prerequisites** | Laboratories 1–5; Docker, Python and `torlab` dependencies |
| **Time** | About 1 hour |
| **File** | `labs/en/lab/exit_policy.py` |

## What This Demonstrates

This lab sends three stream-opening requests through the same exit node, `006e`, to **127.0.0.1**: one destination rejected by a temporary **exit policy**, one allowed destination with a listening server, and one allowed destination with no server. The client sees either `RELAY_END` with a reason or `RELAY_CONNECTED`.

All probes stay on the **disposable Chutney network** using the three-hop path `003r → 005r → 006e`. They do not target public exit relays.

## Preparation

Run from the repository root. Build the container image before first use and do not run multiple language networks simultaneously because host ports overlap.

```bash
# First time only: make -C labs/en/lab image
make -C labs/en/lab start
export PYTHONPATH=labs/en/code
```

The script checks that port `9999` has no listener, creates the required HTTP test server on `8081`, optionally creates another on `8080`, and inserts `ExitPolicy reject 127.0.0.1:8080` **before the first existing `ExitPolicy` directive**. This is a rule for one **address–port pair**, not a blanket prohibition of port 8080 everywhere. It reloads only node `006e`, reading `/lab/net/nodes/006e/pid` and checking the process command line before HUP; it does not use broad `pkill -f` matching.

## Run the Experiment

```bash
python3 labs/en/lab/exit_policy.py
```

## Example Output (Varies Between Runs)

```text
127.0.0.1:8080 -> END reason=EXITPOLICY address=127.0.0.1 TTL=1800
127.0.0.1:8081 -> CONNECTED
127.0.0.1:9999 -> END reason=MISC
```

How to interpret the outcomes:

- **8080 — `EXITPOLICY`:** the exit rejects the target address and port. `RELAY_END` may include an IPv4/IPv6 address and an **optional TTL**. The reference value `1800` is **not guaranteed**; fields can be missing or incomplete under the protocol.
- **8081 — `CONNECTED`:** a TCP stream was established to the locally listening server. It does **not** prove that an HTTP page was fetched.
- **9999 — historical `MISC`:** no server is listening. Tor also defines `CONNECTREFUSED` for a remote connection refusal. The lab accepts **either** `MISC` or `CONNECTREFUSED` for this version-sensitive test, rather than treating `MISC` as a permanent protocol rule.

## A Reference-Version Discrepancy

The original experiment with **tor 0.4.9.13** reported `MISC` where `CONNECTREFUSED` seemed appropriate. Its historical source-code investigation attributed the discrepancy to re-reading `tor_socket_errno` after `getsockopt(SO_ERROR)` returned `ECONNREFUSED`: by the time the END reason was calculated, `errno` was observed as `EINPROGRESS`, leading to the generic `MISC` branch.

This is a **historical implementation analysis**, not a fresh independent audit of the upstream C source or an intrinsic Tor feature. Any differing result should be checked against the running version and relay logs. The specification assigns separate values to `MISC` (1), `CONNECTREFUSED` (3), and `EXITPOLICY` (4).

## Why Three Hops?

The reference one-hop experiment returned `END TORPROTOCOL`. The Tor specification recommends rejecting attempts to open external streams directly on a one-hop circuit, but **does not guarantee that particular reason string**: an implementation may instead destroy the circuit. Using three hops avoids mixing this defense with the exit-policy test.

## Safety, Cleanup and Verification

The script inserts the directive using string slicing rather than a fragile regex replacement, rejects duplicate rules, checks for port conflicts, and closes its sockets and servers. It always attempts to restore the original `006e/torrc` in a `finally` block and reload the specific relay. If the final reload fails, it **raises an error**: a restored file does not prove the running process accepted it. Abrupt termination can bypass cleanup and requires manual inspection of the disposable lab state.

The **Italian** `scripts/verify_labs.py::lab14` still expects the historical **exact** results (`TTL=1800` and `MISC`), so it may falsely fail against a different TTL or `CONNECTREFUSED`. The current teaching script checks the three **outcome categories** instead.

| Symptom | Check |
|---|---|
| Every probe ends with `TORPROTOCOL` | Confirm the circuit has three hops; a one-hop circuit is one possible cause. |
| 8081 is refused | Verify the local server, actual exit configuration and other policy rules; the script refuses to proceed if 8081 is occupied. |
| 9999 does not refuse the connection | Another process may be listening; the script checks before testing. |
| Cleanup/reload fails | Inspect the exact `006e` PID, Tor logs and effective configuration; do not signal unrelated processes. |

References: [Tor Specifications — Closing streams](https://spec.torproject.org/tor-spec/closing-streams.html); [Opening streams](https://spec.torproject.org/tor-spec/opening-streams.html).
