# Laboratory 9 — Triggering Anti-DoS Defenses

| | |
|---|---|
| **Chapter** | 15 — DoS Attacks and Defenses |
| **Requires network?** | Yes, with the image built using `--enable-gpl` |
| **Prerequisites** | Laboratories 1–8 |
| **Time** | About 2 hours |
| **File** | `labs/en/code/torlab/pow.py` |

> **Run this only on your own private network.** The laboratory deliberately generates abnormal traffic. Doing the same against real relays or services would interfere with other users and may be unlawful; see Chapter 25.

## What This Demonstrates

**Experimental boundary:** the 9-of-30 observation is a historical result for a particular Tor build, test timing, rate and previously unmarked IP addresses. Rate limits refill with time, and the configured minimum is per observed client address: do not assume this exact count on a different run. Only run against the disposable, locally owned Chutney network, never any public relay.

Relay anti-DoS defenses can be observed externally, and their actual behavior is slightly more subtle than a casual reading of the documentation suggests. In the source experiment, a burst limit of 10 allowed **9** circuit creations before rejecting the tenth, and connections from 127.0.0.1 were **not** exempt.

The laboratory also examines onion-service proof of work: how it is enabled, what appears in the descriptor, and why the expected work rises approximately linearly.

## Preparation

If the image has not already been built, first run `make -C labs/en/lab image`; `start` expects the image to exist. Check both the PoW module and the GPL-enabled build, not only the Tor version:

```bash
make -C labs/en/lab start
export PYTHONPATH=labs/en/code
```

The image must include the GPL-enabled proof-of-work module. The repository Dockerfile is configured for that build:

```bash
docker run --rm torbook-lab:latest tor --list-modules
docker run --rm torbook-lab:latest tor --version
```

The presence of `pow: yes` in `tor --list-modules` checks the optional PoW module. The GPL build and Equi-X support are separate requirements; `tor --version` should identify a GPL-covered build.

## Part 1 — Circuit-Creation Limits

**Before editing a relay configuration**, ensure the private network is running. The command uses the relay's PID file inside the correct isolated Docker container, avoiding ambiguous process-name matches. The `finally` block restores the file, but a failed reload or forced process termination may require manual inspection and recovery; do not assume cleanup succeeded without checking logs.

The experiment temporarily appends deliberately low anti-DoS limits to `003r`'s `torrc`, reloads the relay, sends 30 consecutive `CREATE_FAST` requests, and restores the original configuration in a `finally` block.

```bash
python3 - <<'EOF'
import subprocess, time
from collections import Counter
from torlab.channel import open_channel
from torlab.cells import Cell, CellCommand
from torlab.laboratory import relay, NODES
from torlab.ntor import create_fast_client

torrc = NODES / "003r" / "torrc"
original = torrc.read_text()
hup = ["docker", "exec", "torbook-network", "sh", "-c",
       "kill -HUP $(cat /lab/net/nodes/003r/pid)"]
try:
    torrc.write_text(original + """
DoSCircuitCreationEnabled 1
DoSCircuitCreationMinConnections 2
DoSCircuitCreationRate 1
DoSCircuitCreationBurst 10
DoSCircuitCreationDefenseType 2
DoSCircuitCreationDefenseTimePeriod 60 seconds
""")
    subprocess.run(hup, check=True); time.sleep(2)
    g = relay("003r")
    for source, channel_count in (("127.0.0.2", 2), ("127.0.0.3", 1), ("127.0.0.1", 2)):
        channels = [open_channel("127.0.0.1", g.port, expected_identity=g.id_ed, source_address=source)
                  for _ in range(channel_count)]
        results, reasons, first_rejection = [], Counter(), None
        for i in range(30):
            x, body = create_fast_client()
            channels[0].send(Cell(0x80000100 + i, CellCommand.CREATE_FAST, body))
            r = channels[0].receive()
            while r.command in (CellCommand.PADDING, CellCommand.VPADDING):
                r = channels[0].receive()
            ok = r.command == CellCommand.CREATED_FAST
            results.append(ok)
            if not ok:
                reasons[r.body[0]] += 1
                first_rejection = first_rejection or i + 1
        m = ", ".join(f"DESTROY({k})" for k in reasons)
        print(f"source {source}, {channel_count} {'channel' if channel_count == 1 else 'channels'}: {results.count(True)} ok, "
              f"{30-results.count(True)} {m or '-'}; first rejection: {first_rejection}")
finally:
    torrc.write_text(original)
    subprocess.run(hup)
EOF
```

```
source 127.0.0.2, 2 channels: 9 ok, 21 DESTROY(5); first rejection: 10
source 127.0.0.3, 1 channel: 30 ok, 0 -; first rejection: None
source 127.0.0.1, 2 channels: 9 ok, 21 DESTROY(5); first rejection: 10
```

**Illustrative historical output, not a deterministic assertion.** The token bucket can refill during the test and the defense may depend on timing and prior state. The code reports what it observes; compare the recorded events, rather than demanding exactly 9 accepts in every execution.

Three details matter:

1. Rejection arrives as **`DESTROY` reason 5**, `RESOURCELIMIT`.
2. With a configured burst of 10, the source experiment accepted **9** circuits. The implementation marks the client once the bucket reaches zero, so the tenth request is already rejected.
3. With **one channel only**, the defense does not activate in this setup because `MinConnections` requires at least two concurrent connections.

The experiment also disproved the initial assumption that loopback connections would be exempt from circuit-creation limits. The implementation in `dos.c` did not provide such an exemption for this defense.

Different source addresses are used so each trial begins with a fresh accounting identity. A marked address remains subject to the configured defense interval.

## Part 2 — Onion-Service Proof of Work

This option is a service setting, not a temporary Python test. Keep a copy of the private `009h/torrc`, reload the process by its PID after making the change, and **restore the original file and reload again** when finished. Rebuild the disposable lab rather than leaving the PoW configuration changed if restoration fails.

The historical `pow-params` line is a sample only. Its base64 seed, UTC expiration timestamp and suggested effort vary. Suggested effort zero denotes no effort demanded at that moment, not definitive proof that the service queue is empty; seed expiration is randomized within the specification's 105–120-minute recommendation window.

```bash
# add to 009h's torrc, after the HiddenService lines...
HiddenServicePoWDefensesEnabled 1
# then: docker exec torbook-network sh -c 'kill -HUP $(cat /lab/net/nodes/009h/pid)'
```

After reloading the service, it publishes a fresh descriptor. Fetching it with [Laboratory 8](Laboratory-08-Onion-services.md) reveals a `pow-params` line in the second layer:

```
pow-params v1 9qe8kJUi30tgcAlInd5a+trFeVl1yjQtPRb0F4u9C7Y= 0 2026-09-24T17:56:10
```

The line contains scheme `v1`, a base64 seed, the suggested effort value, and seed expiry. In the recorded run the suggested effort was zero because the service had not accumulated a queue.

Allow time after `HUP` for the new descriptor to be published and propagated through the private network.

## Part 3 — Work Grows Linearly

**This is only a Monte Carlo simulation of the Blake2b acceptance threshold, not an implementation of Equi-X.** The random 16-byte `solution` is not an Equi-X proof, so no output is a valid introduction proof or a measure of real Equi-X solving cost. The real v1 protocol needs both a correctly solved Equi-X puzzle and the Blake2b check. Here the probability of accepting a uniformly distributed 32-bit `R` is `floor((2**32 - 1)/effort + 1) / 2**32`, approximately `1/effort` for positive effort.

The Python standard library does not implement Equi-X, but the source laboratory isolates the Blake2b-based acceptance layer to illustrate the probability relationship with random candidate solutions.

```bash
python3 - <<'EOF'
import os, statistics
from torlab.pow import required_attempts
id_service, seed = os.urandom(32), os.urandom(32)
for effort in (1, 10, 100, 1000):
    trials = [required_attempts(effort, id_service, seed) for _ in range(400)]
    print(f"effort {effort:>4}: {statistics.mean(trials):.1f} attempts")
EOF
```

```
effort    1: 1.0 attempts
effort   10: 10.5 attempts
effort  100: 90.0 attempts
effort 1000: 1027.7 attempts
```

Exact values vary on every run because the candidates are random, but the expected number of attempts grows approximately in proportion to the configured effort.

One easy mistake is worth preserving from the source: Blake2b with `digest_size=4` is **not** equivalent to truncating a normal 64-byte Blake2b digest to four bytes, because output length is part of Blake2's parameter block and therefore changes the hash computation itself.

## Automated Verification

The Italian `lab9` verifier exercises the live private relay using two channels and a fresh loopback IP, asserting the historical nine accepted cells. This page additionally documents one- and two-channel comparisons and the separate PoW demonstration. The offline `test_pow.py` checks the Blake2b threshold and a statistical approximation (300 simulations for efforts 10 and 40), not circuit DoS or Equi-X.

To run the offline PoW unit tests:

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test/test_pow.py
```

The `lab9` check covers Part 1 and verifies the recorded 9-of-30 acceptance behavior. Parts 2 and 3 are not included in the automated suite: Part 2 changes onion-service configuration and waits for descriptor publication; Part 3 is statistical and has no single deterministic output.

## Known Problems

| Symptom | Cause |
|---|---|
| All 30 circuits are rejected immediately | The source address may still be marked from a previous trial. Wait for the configured interval or use another test-only loopback source. |
| No rejection with two channels | The relay may not have reloaded the modified configuration; inspect `003r`'s `notice.log`. |
| No `pow-params` line in the descriptor | The image may lack `--enable-gpl`, or the new descriptor has not yet been published. |
