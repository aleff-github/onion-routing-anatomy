# Laboratory 5 — Downloading a File: Streams, Windows, and SENDME

| | |
|---|---|
| **Chapter** | 11 — Streams and Flow Control |
| **Requires network?** | Yes, plus a local web server |
| **Prerequisites** | Laboratories 1–4 |
| **Time** | About 3 hours to implement; about 2 minutes to rerun |
| **File** | `labs/en/code/torlab/stream.py` |

## What This Demonstrates

The educational client can download a full megabyte through three relays and receive the same SHA-256 digest as the original file. The second experiment does something an ordinary client should not do: it **stops sending `SENDME` cells** and counts how many `DATA` cells the exit sends before pausing. That number exposes the active window and makes the difference between historical flow control and newer congestion control directly visible.

## Preparation

Run this experiment only against the **private Chutney Tor network** from Laboratories 1–4. If that network is stopped, start the matching `labs/en/lab` environment first; the educational client is not intended for the public Tor network. Run the web server on the same host as the client and the lab relay, using the configured host network.

Start a local web server on port 8080 containing a one-megabyte file:

```bash
mkdir -p /tmp/labweb && head -c 1048576 /dev/urandom > /tmp/labweb/grande.bin
sha256sum /tmp/labweb/grande.bin
cd /tmp/labweb && python3 -m http.server 8080 --bind 127.0.0.1 &
```

Then, from the repository:

```bash
export PYTHONPATH=labs/en/code
```

> Port 8080 is also used by `make verify-labs`. Stop this temporary server before running the verification suite, otherwise the suite will fail immediately because the port is already in use.

## Run the Experiment

```bash
python3 - <<'EOF'
import hashlib
import time
from pathlib import Path
from torlab.circuit import build
from torlab.laboratory import relay
from torlab.stream import Stream

circ = build([relay("003r"), relay("004r"), relay("006e")])
s = Stream(circ, 1)
t = time.time()
s.open("127.0.0.1", 8080)
s.send(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
r1 = s.receive_all()
print(f"stream 1: {len(r1)} byte in {time.time()-t:.2f} s, DATA cells {s.reg.data_cells}, "
      f"circuit SENDME so far {circ.sendme_sent}, other {s.reg.others}")

s = Stream(circ, 2)  # second stream, same circuit
t = time.time()
s.open("127.0.0.1", 8080)
s.send(b"GET /grande.bin HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
r2 = s.receive_all()
print(f"stream 2: {len(r2)} byte in {time.time()-t:.2f} s, DATA cells {s.reg.data_cells}, "
      f"circuit SENDME so far {circ.sendme_sent}, other {s.reg.others}")

headers, sep, payload = r2.partition(b"\r\n\r\n")
if not sep or b" 200 " not in headers.split(b"\r\n", 1)[0]:
    raise RuntimeError("HTTP response is missing or is not 200 OK")
reference = Path("/tmp/labweb/grande.bin").read_bytes()
assert len(reference) == len(payload) == 1048576, "HTTP file length differs"
expected_sha = hashlib.sha256(reference).hexdigest()
received_sha = hashlib.sha256(payload).hexdigest()
assert received_sha == expected_sha, "download SHA-256 does not match local file"
print("sha256 received:", received_sha)
print("SHA-256 matched local file")
EOF
```

## Expected Output

The output below is illustrative: the file is random, the HTTP headers and directory listing vary, and cell counts depend on packing and network scheduling. The SHA-256 value is computed and checked at runtime.

```text
stream 1: ... DATA cells 1, ... circuit SENDME so far 0, ...
stream 2: ... DATA cells 2120, ... circuit SENDME so far 68, ...
sha256 received: <64-character digest of the newly generated file>
SHA-256 matched local file
```

- A successful `BEGIN` receives `CONNECTED`. An IPv4 response may contain 8 bytes (address plus TTL), but the specification also allows an empty body and an IPv6 format; `7f000001 00000708` is **one historical example**, not a fixed response or fixed TTL.
These counters refer to cells **originated by the final hop for streams on this circuit**, not transit cells from earlier hops. The example uses both streams through the same exit.

With an illustrative run of 1 + 2120 DATA cells and an agreed increment of 31, 68 = floor(2121 / 31) circuit SENDMEs are sent. Those values are examples, not fixed constants. A transfer of 1048781 HTTP bytes needs at least ceil(1048781 / 498) = 2106 DATA cells; 2120 illustrates partially filled cells rather than defining their required count.

## The Mistake That Makes the Laboratory Worthwhile

The first implementation stored the circuit-`SENDME` counter on the **stream**. The first stream, which required only a couple of cells, worked. The second stream, carrying a megabyte, was terminated by the exit with `DESTROY`.

The reason is that circuit `SENDME` counts `DATA` cells from **all streams on the circuit**. The exit had already counted cells from stream 1 and therefore expected the next `SENDME` earlier in stream 2. The client sent it too late and attached a different running digest from the one expected. Proposal 289 requires the peer to close the circuit in that situation. Moving the counter to `Circuit` fixed the bug.

Circuit `SENDME` cells are **authenticated**: they carry the running digest associated with the triggering cell. A party that has not actually received and processed the traffic cannot trivially forge them to make the sender transmit faster.

## Looking Directly at the Windows

```bash
python3 - <<'EOF'
from torlab.circuit import build
from torlab.laboratory import relay
from torlab.stream import Stream
for cc in (True, False):
    circ = build([relay("003r"), relay("004r"), relay("006e")], cc=cc)
    circ.count_received_data = lambda: None       # never send a SENDME
    s = Stream(circ, 1)
    s.open("127.0.0.1", 8080)
    s.send(b"GET /grande.bin HTTP/1.0\r\n\r\n")
    circ.channel.sock.settimeout(6)
    try:
        s.receive_all()
    except TimeoutError:
        pass
    print(f"congestion control={cc}: the exit stops after {s.reg.data_cells} DATA cells")
EOF
```

The following sample stopping points assume this private Tor network uses an initial congestion window of 124 cells (4 × `sendme_inc = 31`) and a legacy stream window of 500. Consensus parameters, Tor version, and test conditions may alter measurements.

```text
congestion control=True: the exit stops after 124 DATA cells\ncongestion control=False: the exit stops after 500 DATA cells
```

**124** means four increments of 31 DATA cells, **not** literally four TLS records. **500** arises from the separate legacy stream window being exhausted ahead of the nominal circuit window of 1000. The exit stops originating new DATA cells while waiting for acknowledgements; this does not guarantee that all pending bytes reside in its application buffer.

This educational `Stream` class **does not implement stream-level SENDME**. That is appropriate for the negotiated congestion-control case (`cc=True`), but when `cc=False` it intentionally cannot complete a large legacy-flow-control transfer: the stream stalls at the 500-cell window even if circuit SENDMEs were enabled. This is a demonstration limitation, not a production implementation.

## Automated Verification

The Italian verifier `lab5` is implemented in `scripts/verify_labs.py`: it checks the download hash and the fixed 124/500 sample assumptions on the private network. This translated edition exposes a separate manual Chutney experiment and Python modules; there is no automatically equivalent per-language `lab5` command.

## Known Problems

| Symptom | Cause |
|---|---|
| `BEGIN rejected: EXITPOLICY` | The exit's policy rejected the destination address or port; check the [Laboratory 14](Laboratory-14-Exit-policy.md) configuration. |
| Circuit is destroyed during a large download | Circuit `SENDME` counter was implemented per stream rather than per circuit. |
| `BEGIN rejected: CONNECTREFUSED` | The exit could not establish a TCP connection to 127.0.0.1:8080; verify the test HTTP server is reachable. |

---

# Implementation, in Detail

The relevant code is `labs/en/code/torlab/stream.py` (about 80 lines) plus the circuit-`SENDME` logic in `circuit.py`. This is where the educational client moves from protocol demonstration to transferring real files.

## Opening a Stream

```python
def begin_body(address: str, port: int, flag: int = 0) -> bytes:
    """NUL-terminated lowercase ADDRPORT; omit FLAGS when zero."""
    body = f"{address.lower()}:{port}".encode() + b"\x00"
    return body + (struct.pack(">I", flag) if flag else b"")

```

Three details in the encoder, with the correct normative strength:

- **Lowercase (SHOULD):** Tor recommends sending `ADDRPORT` in lowercase to reduce fingerprinting; a receiver **MUST** accept mixed case. Lowercase is not a mandatory rejection rule.
- **NUL-terminated:** the field is a C-style string rather than a separately length-prefixed string.
- **FLAGS omitted when zero:** this optional field is only needed when requesting additional address-family behavior such as IPv6 support.

```python
def open(self, address: str, port: int) -> bytes:
    self.circ.send(RelayMessage(RelayCommand.BEGIN, self.id, begin_body(address, port)))
    _, msg = self._next()
    if msg.command == RelayCommand.END:
        raise CircuitError(f"BEGIN rejected: {END_REASONS.get(msg.data[0], msg.data[0])}")
    if msg.command != RelayCommand.CONNECTED:
        raise CircuitError(f"unexpected response to BEGIN: {msg.command}")
    return msg.data
```

There is an intentional difference between this educational client and tor that matters for client fingerprinting. The specification requires `EXTEND2` to travel in `RELAY_EARLY`, and recommends using the remaining early-cell allowance for roughly the first eight origin-side relay messages not destined for the first hop. tor follows that recommendation: in `src/core/or/relay.c`, it sends a `RELAY_EARLY` while `remaining_relay_early_cells > 0` for cells with `cpath_layer != origin_circ->cpath`. As a result, tor normally sends the initial `BEGIN` using `RELAY_EARLY`, whereas this teaching client uses ordinary `RELAY` except for `EXTEND2`.

The consequence is real: a guard counting early cells could distinguish this simplified client from tor. The implementation keeps the simpler behavior so each laboratory introduces one idea at a time, but the book's complete-session figure shows the production behavior.

The exit answers with `CONNECTED`, whose body contains the resolved address and TTL, or with `END` and a reason code. Those reasons matter operationally: `EXITPOLICY` means this exit refuses the destination and another exit may work, whereas `CONNECTREFUSED` means the chosen exit reached the destination and the remote endpoint refused the connection. See [Laboratory 14](Laboratory-14-Exit-policy.md) for a direct exit-policy experiment.

The protocol also allows a client to send application data before `CONNECTED` arrives to save one circuit round trip. This educational client waits for `CONNECTED` first for clarity.

## Flow Control, and the Bug That Matters

```python
def count_received_data(self) -> None:
    """Call for each DATA cell received from the final hop: send a SENDME
    authenticated (version 1) every `sendme_inc` cells."""
    est = dict(self.exit_extensions)
    sendme_inc = est[2][0] if 2 in est else 100
    self.data_to_ack += 1
    if self.data_to_ack == sendme_inc:
        self.data_to_ack = 0
        # The digest is the running digest after the triggering recognized cell (the one that
        # triggers SENDME): sendme_digest in src/core/crypto/relay_crypto_tor1.c.
        digest = self.crypto.hops[-1].backward.digest.digest()
        body = struct.pack(">BH", 1, 20) + digest
        self.send(RelayMessage(RelayCommand.SENDME, 0, body))
        self.sendme_sent += 1
```

**This method belongs to `Circuit`, not `Stream`.** The original bug placed the counter on each stream independently, which produced the wrong digest timing after one stream had already consumed part of the circuit allowance.

The remaining elements are equally important:

- **`sendme_inc`** comes from extension 2 negotiated with the exit during the handshake ([Laboratory 3](Laboratory-03-Handshake.md)). It is 31 with congestion control and 100 for historical flow control in this setup. It is negotiated state, not a hard-coded property of the client.
- **The digest** is the final hop's running backward-direction digest *after* processing the triggering `DATA` cell. It is internal circuit state known only to a party that processed the corresponding traffic.
- **Version 1 and length 20** encode the authenticated SHA-1-based circuit `SENDME` format. Version 0 lacked the digest and was vulnerable to forged acknowledgements; Proposal 289 introduced authenticated acknowledgements.
- **StreamID zero** identifies a circuit-control message. Streams have their own windows and stream-level acknowledgements.

> An authenticated `SENDME` is not a digital signature. It is closer to a **proof of receipt**: knowing the required running digest demonstrates that the receiver processed the relevant cells.

## The Receive Loop

```python
def receive_all(self) -> bytes:
    """Read DATA until END, sending circuit SENDME messages when required."""
    parts = []
    while not self.closed:
        _, msg = self._next()
        if msg.command == RelayCommand.DATA:
            parts.append(msg.data)
            self.reg.received_data += len(msg.data)
            self.reg.data_cells += 1
            self.circ.count_received_data()
        elif msg.command == RelayCommand.END:
            self.closed = True
            self.reg.others.append(f"END {END_REASONS.get(msg.data[0] if msg.data else 1)}")
        else:
            self.reg.others.append(RelayCommand(msg.command).name)
    return b"".join(parts)
```

Counting and acknowledging happen **inside** the receive loop. If the client stops reading, it also stops acknowledging, and the sender eventually reaches its window limit. Flow control therefore emerges naturally from the receive path.

`self.reg` gathers statistics—bytes, `DATA` cells, and other messages—which lets the laboratory show why real transfers often use more cells than the minimum ceil(bytes / 498): exits send data as it arrives rather than waiting to fill every relay cell.

## Measuring a Window

```python
circ = build(path, cc=cc)
circ.count_received_data = lambda: None      # no SENDME messages
```

Replacing the method with a no-op is a laboratory-only technique. It directly answers a question that is otherwise easy to leave abstract: **how many cells will the exit send before flow control stops it?**

The observed answer—124 with congestion control and 500 without it—depends on which active window is exhausted first. The 500-cell result surprises anyone expecting the 1000-cell historical circuit window: in this experiment, the stream window becomes the limiting factor first.

## What You Need to Know to Make It Work

- You need a **server on port 8080**. That is also the port used by `make verify-labs`, so stop your manual server before running the full suite.
- The test file must be large enough to exceed the active window. With fewer than roughly 124 cells (~60 KB), the congestion-control experiment reveals little.
- StreamIDs must be **distinct and nonzero** for streams on the same circuit.
- If a large transfer ends with `DESTROY`, verify that circuit `SENDME` accounting is shared across streams rather than maintained independently.

## Where These Rules Come From

| In the code | In the specification |
|---|---|
| `BEGIN`, `CONNECTED`, ADDRPORT format | tor-spec, *Opening streams and transmitting data* |
| `END` reasons | tor-spec, *Closing streams* |
| Windows and `SENDME` | tor-spec, *Flow control* |
| Authenticated `SENDME` | Proposal 289 |
| Congestion control and `sendme_inc` | Proposal 324 |
