# Laboratory 11 — Live Stream Isolation

| | |
|---|---|
| **Chapter** | 18 — Controlling tor: ControlPort and Stem |
| **Requires network?** | Yes |
| **Prerequisites** | Running laboratory network; `stem` (already installed inside the container) |
| **Time** | About 1 hour |
| **File** | `labs/en/lab/isolation.py` |

## What This Demonstrates

tor does not place all application traffic onto the same circuit. It isolates streams according to the **SOCKS credentials** used by the application. Tor Browser uses this mechanism for first-party isolation: different site contexts receive different SOCKS credentials. When `IsolateSOCKSAuth` is enabled (normally the default), streams with different credentials **cannot share a circuit**. This does not guarantee a separate circuit per tab or different exit relay IP addresses.

The laboratory also makes another subtle point visible: with Conflux enabled, a stream may be carried over a **Conflux tunnel** with linked circuit legs. Compare the logical tunnel when interpreting isolation, not just one leg.

## Preparation

```bash
# On first use: make -C labs/en/lab image
make -C labs/en/lab start
# a web server on port 8080, the destination used by the tests
python3 -m http.server 8080 --bind 127.0.0.1 &
```

The script runs **inside the container** because it uses `stem` to communicate with the client's ControlPort. The container uses Docker host networking and mounts `labs/en/lab` as `/lab`; its script **is not at** `/labs/en/lab/`. The Python code passes `--noproxy ""` to curl so that `NO_PROXY` cannot bypass SOCKS for the loopback destination:

```bash
docker exec -w /lab torbook-network python3 /lab/isolation.py
```

## Example Output (Varies Between Runs)

```
credentials site-a.example  -> conflux 90EFE5BD       ['test004r', 'test005r', 'test007e']
credentials site-a.example  -> conflux 90EFE5BD       ['test004r', 'test005r', 'test007e']
credentials site-b.example  -> conflux A608C1C1       ['test004r', 'test006e', 'test007e']
credentials -               -> conflux 2FED7F85       ['test004r', 'test003r', 'test007e']
(NEWNYM delayed by 6 s)
after NEWNYM, site-a.example  -> conflux BA715C26
```

How to interpret it:

- The first two requests use the **same** credentials and happen to receive the **same** tunnel. Reuse is **allowed, not guaranteed**: Tor may construct or select a different compatible tunnel.
- Requests carrying different credentials must not share circuits when `IsolateSOCKSAuth` is enabled; the different identifiers observed here illustrate that rule. They do not imply distinct exit relay IPs.
- After `NEWNYM`, **new application requests** should use clean circuits. This signal is **not equivalent** to Tor Browser's New Identity action, which also closes tabs/windows and clears browser data such as cookies.
- `conflux XXXXXXXX` displays only the first eight characters of a `CONFLUX_ID`; the relay list is one leg of a linked pair. If Conflux is unavailable, the script can print `circuit N` instead.

## Three Traps Found During the Experiment

This laboratory originally failed intermittently for three distinct reasons:

1. **tor opens its own streams.** Directory activity generates `STREAM` events too. Counting every event produced incorrect results, so the script filters by destination and uses the relevant final event.
2. **`NEWNYM` can be rate-limited.** The Tor version used for the original experiment had a 10-second `MAX_SIGNEWNYM_RATE` interval; the control specification allows rate limiting without guaranteeing that exact interval in every version. An early signal was observed to be **deferred**, potentially overlapping the next request. The script watches for a corresponding notice and waits, but absence of a notice alone does not prove that a signal has already taken effect.
3. **Conflux.** Circuits are linked through `CONFLUX_LINKED`. Isolation operates on the logical tunnel; looking only at individual legs can make correct isolation appear broken.

Some residual variation remains on such a tiny network because tor has very few relay combinations available. The automated check accounts for this by retrying up to three times rather than treating every one-off path choice as a protocol failure.

## Automated Verification

The `lab11` check in the **Italian** `scripts/verify_labs.py` evaluates three observations from this experiment: reuse of the same tunnel, separation of different credentials, and a new tunnel following `NEWNYM`. The first is not a Tor guarantee: identical credentials may legitimately use different compatible circuits. **This translated `isolation.py` only prints observations; it does not validate invariants or exit nonzero when they fail.** `make -C labs/en/lab verify` runs Chutney's network verification, not the Italian `lab11` check.

## Known Problems

| Symptom | Cause |
|---|---|
| The script finds no streams | The server on port 8080 is missing, or the destination configured in the script does not match it. |
| Different credentials appear on the same tunnel | Rare path-selection effects can occur on this very small network; rerun the experiment. |
| `SocketError` on the ControlPort | The script is running on the host rather than inside the container. |
