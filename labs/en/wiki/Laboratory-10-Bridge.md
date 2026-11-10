# Laboratory 10 — An obfs4 Bridge Through a Censor's Eyes

| | |
|---|---|
| **Chapter** | 16 — Censorship and Pluggable Transports |
| **Requires network?** | Yes, but a **different** topology: `book-bridge` |
| **Prerequisites** | [Laboratory 1](Laboratory-01-Channel.md) |
| **Time** | 1–2 hours |
| **File** | `labs/en/lab/` plus the localized bridge verification workflow |

## What This Demonstrates

This private-network experiment contrasts TLS traffic to an ordinary ORPort with obfs4 traffic. The reference capture showed a TLS record starting with `16 03 01` and no TLS-looking header on the obfs4 flow. **Those bytes, and a zero count from one dissector, are observations rather than universal fingerprints or proof of indistinguishability.** Traffic analysis, known bridge IPs and active blocking remain possible.

A generic TLS probe did not complete the obfs4 handshake in the reference run. The obfs4 specification requires invalid handshakes to be discarded and **recommends** a randomized delay before closing a failed connection; it does not require a connection to remain silent forever.

## Preparation

**Network safety:** `make ... clean` deletes the generated `lab/net/`, including private lab keys and logs. Run only on a disposable local Chutney network and back up anything you intend to keep. First build the image with `make -C labs/en/lab image` if necessary; `start` does not build it. Do not run different language networks at once, because they share host ports.

This laboratory uses a separate topology containing a bridge authority (`003ba`), an obfs4 bridge (`009br`), and a bridge client (`011bc`).

```bash
make -C labs/en/lab clean
make -C labs/en/lab start NETWORK=book-bridge
```

To return manually to the ordinary network afterward:

```bash
make -C labs/en/lab clean
make -C labs/en/lab start
```

Once `book-bridge` is running, `make -C labs/en/lab verify` runs Chutney's end-to-end checks against that active topology.

In this topology, the bridge client uses **SocksPort 9011**, while the bridge's obfs4 transport listens on **9909**.

## Step 1 — The Client Connects Through the Bridge

```bash
grep -E "new bridge descriptor|Only one bridge|Bootstrapped 100" labs/en/lab/net/nodes/011bc/notice.log
```

```
[notice] new bridge descriptor 'test009br' (fresh): $DE539956E7E6A323...~test009br at 127.0.0.1
[warn] Only one bridge (transport: 'obfs4') is configured. You should have at least two
       for conflux, for any transport that is not 'snowflake'.
[notice] Bootstrapped 100% (done): Done
```

The log shows successful bridge descriptor acquisition and bootstrap. **It does not, on its own, prove which connection carried the descriptor.** Bridge addresses and obfs4 transport parameters must already be configured or supplied out of band; the bridge is not listed in the ordinary public consensus. The Conflux warning concerns using only one bridge in this setup, not bootstrap failure.

```bash
docker exec torbook-network curl -s -o /dev/null -w "%{http_code}\n" \
  --noproxy "" --socks5-hostname 127.0.0.1:9011 http://127.0.0.1:8080/
```

```
200
```

A local HTTP server must be listening on port 8080 for this check.

## Step 2 — What the Censor Sees

In a separate terminal start a local-only HTTP server with `python3 -m http.server 8080 --bind 127.0.0.1`. The capture below **overwrites** `b1.pcap`; preserve previous evidence before repeating it. Generate both flows during tcpdump's recording window and let the capture finish before analyzing it:

Capture, from inside the container, both traffic to the bridge's obfs4 port and traffic to a normal relay ORPort while generating both kinds of connection:

```bash
# Capture runs only on the local, disposable Chutney network
docker exec -u 0 -d torbook-network sh -c \
  "timeout 25 tcpdump -i lo -w /lab/net/b1.pcap 'tcp port 9909 or tcp port 5104' >/dev/null 2>&1"
sleep 2
docker exec torbook-network curl --silent --show-error --max-time 15 \
  --noproxy "" --socks5-hostname 127.0.0.1:9011 http://127.0.0.1:8080/
# Also open a normal Tor channel to the local relay
PYTHONPATH=labs/en/code python3 - <<'PY'
from torlab.channel import open_channel
from torlab.laboratory import relay
r = relay("004r", client="010c")
open_channel("127.0.0.1", r.port, expected_identity=r.id_ed)
PY
sleep 27  # wait for tcpdump to finish before reading
for p in 5104 9909; do
  echo "== port $p =="
  docker exec torbook-network tshark -r /lab/net/b1.pcap \
    -Y "tcp.dstport==$p && tcp.len>0" -T fields -e tcp.len -e tcp.payload | head -1
  docker exec torbook-network tshark -r /lab/net/b1.pcap \
    -Y "tls && tcp.port==$p" -T fields -e frame.number | wc -l
done
```

The bytes, frame counts and segment sizes below come from a reference capture and vary between runs. In particular `16 03 01` identifies a TLS handshake record's **legacy version field**, not the negotiated TLS version. The presence or absence of `tls` in a Wireshark display filter is a heuristic and cannot prove that the flow is unidentifiable. obfs4 hides protocol structure but **does not conceal the destination IP** from an observer who already knows the bridge.

```
== port 5104, first bytes from the client ==
1533   16030105f8010005f4030305cc9ad005e921614509b15f6151135f983b...
== port 9909, first bytes from the client ==
602    f23abb4e8c3a45ab0e92958157c177bba1cc5dd27e80d74db45d77b425...

== packets recognized as TLS ==
port 5104: 29
port 9909: 0

== obfs4 segment sizes (client -> bridge) ==
602 1762 1308 1414 643 2183 2195 1568 1308 2037 616 1346
```

How to interpret the capture:

- **`16 03 01`** is the start of a TLS handshake record. Traffic to the normal ORPort is recognized as TLS, giving a censor both protocol-level structure and an address that may already be known as a public Tor relay.
- Traffic to the obfs4 port begins with no comparable TLS structure. In the recorded capture, **zero** packets were identified as TLS, and segment sizes did not map cleanly to 514-byte Tor cells.
- Exact bytes, packet counts, and segment sizes vary between runs. The meaningful observation is the contrast between recognizable TLS and the obfuscated transport.

## Step 3 — Actively Probing the Bridge

A censor suspecting a bridge might try to connect and speak some known protocol. Using the ordinary Tor-channel code from [Laboratory 1](Laboratory-01-Channel.md) against the obfs4 port gives:

```bash
PYTHONPATH=labs/en/code python3 - <<'PY'
import ssl
from torlab.channel import ChannelError, open_channel
from torlab.laboratory import relay
r = relay("004r", client="010c")
try:
    open_channel("127.0.0.1", 9909, expected_identity=r.id_ed)
    raise AssertionError("unexpected plain TLS channel through obfs4 port")
except (TimeoutError, ssl.SSLError, ConnectionResetError, ChannelError) as exc:
    print(type(exc).__name__ + ":", exc)
PY
```

```
TimeoutError: _ssl.c:1063: The handshake operation timed out
```

The bridge does not provide a protocol error or banner. To obfs4, this TLS ClientHello is simply an invalid transport handshake, and the observed behavior is silence until the caller's timeout. Without the bridge's transport parameters, including its certificate material, a valid obfs4 handshake cannot simply be synthesized by an unauthenticated generic TLS probe.

## Automated Verification

A TLS ClientHello is not a valid obfs4 handshake. In the reference run no useful protocol response arrived before timeout; a reset or delayed close is also possible. The exact `_ssl.c` line number is runtime-dependent. This single test demonstrates only a failed generic TLS probe, **not proof that a censor could learn nothing** or could not block a known address. A valid obfs4 client requires the bridge's distributed transport parameters, including its certificate material.

`make -C labs/en/lab verify` calls **Chutney's topology verification** on the currently active `book-bridge` network. It is **not** the six-check Italian `make verifica-lab-bridge` workflow, and it does not by itself perform both traffic captures or a TLS active-probe experiment.

```bash
make -C labs/en/lab verify      # verifies the active bridge topology
```

The `verify` command does not switch topologies. Start `book-bridge` explicitly as shown above, verify it, then clean it and start the ordinary `book` topology again when the laboratory is complete.

## Known Problems

If the topology cannot start, use the disposable network's `make -C labs/en/lab clean` procedure and inspect port ownership; `pkill -x tor` affects **every Tor process in that container**, not only one bridge. Never issue it in a container carrying other workloads.

| Symptom | Cause |
|---|---|
| Bridge-network bootstrap never completes | `tor` processes from the previous topology may still own the ports. On the disposable lab network, stop them with `docker exec torbook-network pkill -x tor`. |
| `011bc` does not start | Client nodes belong to startup phase 2: `CHUTNEY_LAUNCH_PHASE=2 chutney start`. |
| `tshark` finds no packets | Capture may have started after the traffic. Start `tcpdump`, wait briefly, then generate the connections. |
| Node numbers differ from this page | Chutney numbering follows ordering in `labs/en/lab/chutney/networks/book-bridge`; inspect `labs/en/lab/net/nodes/`. |
