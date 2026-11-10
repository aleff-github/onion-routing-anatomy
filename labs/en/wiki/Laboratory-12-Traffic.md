# Laboratory 12 — Cells Inside TLS

| | |
|---|---|
| **Chapter** | 20 — Analyzing Tor Traffic |
| **Requires network?** | Yes |
| **Prerequisites** | Laboratories 1–4 |
| **Time** | 1–2 hours |
| **File** | `labs/en/code/torlab/traffic.py` |

## What This Demonstrates

This laboratory looks inside a Tor connection from the outside **while holding the session keys**. We capture our own traffic with `tcpdump`, export TLS session keys from our own client through `SSLKEYLOGFILE`, and let `tshark` decrypt the capture. The Tor cells then become visible one by one in handshake order.

This is the appropriate way to perform the experiment: decrypt **your own** traffic using keys that your own program intentionally exports. No third-party traffic is intercepted or attacked.

## Preparation

Run these commands from the repository root against the **private** lab network. Build the image before its first start. Do not run other language editions simultaneously: their host ports overlap.

```bash
# First use only: make -C labs/en/lab image
make -C labs/en/lab start
export PYTHONPATH=labs/en/code
```

**Security and state:** this example replaces `labs/en/lab/net/capture.pcap` and `keys.log` from the previous run. Save previous results first if needed. **Never publish the TLS key log**, which can decrypt the captured session. The project mounts this directory inside the container as `/lab`, not `/labs/en/lab`. The output below is historical, not guaranteed.

## Run the Experiment

```bash
python3 - <<'PY'
import os, subprocess, time
from torlab.cells import CellCommand as C
from torlab.circuit import build
from torlab.laboratory import relay, NODES
from torlab.traffic import cells_from_follow as parse

network = "torbook-network"
keys = NODES.parent / "keys.log"
capture = NODES.parent / "capture.pcap"
# These are disposable experiment files; old versions are overwritten.
keys.unlink(missing_ok=True)
capture.unlink(missing_ok=True)

# 1. capture only local relay port 5104
subprocess.run(["docker", "exec", "-u", "0", "-d", network, "sh", "-c",
                "timeout 12 tcpdump -i lo -w /lab/net/capture.pcap 'tcp port 5104'"],
               check=True)
time.sleep(2)

# 2. open a private channel and export its TLS keys
previous = os.environ.get("SSLKEYLOGFILE")
os.environ["SSLKEYLOGFILE"] = str(keys)
try:
    circuit = build([relay("004r")], cc=False)
    circuit.channel.sock.close()
finally:
    if previous is None:
        os.environ.pop("SSLKEYLOGFILE", None)
    else:
        os.environ["SSLKEYLOGFILE"] = previous
# Allow the timed capture to finish before tshark opens the file.
time.sleep(12)
if not keys.exists() or not keys.stat().st_size:
    raise RuntimeError("No TLS session secrets exported")
keys.chmod(0o600)
print("TLS key log lines:", len(keys.read_text().splitlines()))

# 3. find TLS TCP streams and reconstruct Tor cells
opts = ["-r", "/lab/net/capture.pcap", "-d", "tcp.port==5104,tls",
        "-o", "tls.keylog_file:/lab/net/keys.log"]
scan = subprocess.run(["docker", "exec", network, "tshark", *opts,
                       "-Y", "tls && tcp.port==5104", "-T", "fields", "-e", "tcp.stream"],
                      check=True, capture_output=True, text=True)
stream_ids = sorted({int(v) for v in scan.stdout.split() if v.isdigit()})
found = False
for stream_id in stream_ids:
    result = subprocess.run(["docker", "exec", network, "tshark", *opts,
                             "-q", "-z", f"follow,tls,raw,{stream_id}"],
                            check=True, capture_output=True, text=True)
    try:
        cells = parse(result.stdout)
        names = [(direction, C(cell.command).name)
                 for direction, cell, _ in cells]
    except (ValueError, IndexError):
        continue
    if len(names) >= 2 and [name for _, name in names[:2]] == ["VERSIONS", "VERSIONS"] \
            and "CREATED2" in [name for _, name in names]:
        print(f"flow {stream_id}:")
        for direction, cell, version in cells:
            print(f"  {direction} {C(cell.command).name} (body {len(cell.body)} byte)")
        found = True
        break
if not found:
    raise RuntimeError("No complete VERSIONS / CREATED2 sequence found; inspect capture and key log")
PY
```

## Example Output (Varies Between Runs)

```
TLS keys exported: 6 lines
flow 1:
   client VERSIONS (body 4 byte)
   relay VERSIONS (body 6 byte)
   relay CERTS (body 1446 byte)
   relay AUTH_CHALLENGE (body 36 byte)
   relay NETINFO (body 509 byte)
   client NETINFO (body 509 byte)
   client CREATE2 (body 509 byte)
   relay CREATED2 (body 509 byte)
```

How to interpret it:

- This is the handshake from [Laboratory 1](Laboratory-01-Channel.md), observed from the packet-capture side: the same cells, in the same order, reconstructed from bytes carried inside TLS.
- TLS stream indices vary. The example discovers **all** TCP stream indices recognized as TLS on relay port 5104 and selects one that contains both `VERSIONS` cells and `CREATED2`. It does not assume the right connection lies among indices 0–7 and raises an error if no complete sequence is found.
- `NETINFO`, `CREATE2`, and `CREATED2` have **509-byte padded bodies** in fixed-length cells. With Tor link protocol v4/v5, the **whole fixed-length cell is 514 bytes** (4-byte CircID, 1-byte command, 509-byte body). `VERSIONS` and `CERTS` are variable-length cells. Without session keys, a passive observer cannot read the encrypted cell commands.
- The **six lines** shown here are from a previous capture, not a universal TLS key count. The number can vary by TLS version, implementation and session; the file may include comments. In this project the Python client's `ssl.SSLContext.keylog_filename` writes the key log.

## What Is Visible *Without* the Keys?

This is the central question of Chapter 20. A passive observer sees the relay address and port, a TLS connection (TLS 1.3 in the historical capture), and packet sizes and timing. The relay in this experiment belongs to the **private** lab, not the public Tor consensus. Without session keys, they do not see Tor cell commands, CircIDs, or how many logical circuits share the channel.

Sizes and timing still matter. They are the raw material for end-to-end traffic-correlation attacks explored defensively in [Laboratory 16](Laboratory-16-Correlation.md).

## Automated Verification

The `lab12` check belongs to the **Italian** `scripts/verify_labs.py`: it looks for two initial `VERSIONS` cells and a `CREATED2`, but the historical verifier checks only the first eight stream indices and does not reliably propagate every command failure. The example here scans detected streams and fails if no complete sequence is found; `make -C labs/en/lab verify` only invokes Chutney.

## Known Problems

| Symptom | Cause |
|---|---|
| No cells appear in any TLS stream | Ensure Python exported keys before opening the socket, that TLS is decoded on port 5104, and that the capture includes the complete handshake. |
| `tshark` cannot open the pcap | Packet capture inside the container requires root privileges; the command uses `docker exec -u 0`. |
| The pcap is empty | `tcpdump` started after the traffic. Begin capture first and leave a short delay before generating the connection. |
| Only part of the handshake is decrypted | The capture ended while the channel was still active; increase the capture timeout. |
