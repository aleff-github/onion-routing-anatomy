# Private Tor Network for the Laboratories

The English edition's active experiments are **intended only for the controlled private Chutney network**, never for public Tor relays or third-party services. The detailed setup is described in Chapter 19; this file is a quick reference. **Docker uses `--network host`, so the container shares the host's network namespace: this is not network isolation.** Run these experiments only on a controlled test host.

## Contents

| File or directory | Purpose |
| --- | --- |
| `Dockerfile` | Builds Tor 0.4.9.13 from source with `--enable-gpl` (needed by the onion-service proof-of-work module); includes Chutney, obfs4proxy, snowflake-client, Stem, tshark and curl |
| `Makefile` | Targets `image`, `start`, `verify`, `status`, `shell`, `stop` and `clean` |
| `chutney/networks/book` | Default network for most laboratories |
| `chutney/networks/book-bridge` | Bridge authority, obfs4 bridge and bridge client for Laboratory 10; no onion service |
| `net/` | Generated node configurations, private keys, logs and state; not versioned |
| `*.py` | Exercises for Laboratories 11, 13, 14, 16, 17, 18 and 20 |

## Commands

From `labs/en/lab/` (or use `make -C labs/en/lab <target>` from the repository root):

```bash
make image     # Build the private lab image before first use
make start     # Start the standard Chutney topology and bootstrap
make verify    # Chutney end-to-end network check, NOT all laboratory exercises
make status    # Chutney node status
make shell     # Open a shell in the lab container
make stop      # Stop the nodes and remove the container; preserve net/
make clean     # Stop and DELETE net/, including generated keys and identities
```

For Laboratory 10, use `make start NETWORK=book-bridge` **only after stopping the previous network and examining/removing its disposable state**. The bridge topology has **12 nodes**, not 10, and does not include the onion service. The Italian root `make riavvia` target operates on the **Italian** container, not this English environment; do not use it to restart this network.

The EN, RU and ZH-CN laboratory Makefiles use the same Docker image and container names (`torbook-lab:latest`, `torbook-network`) and overlapping host ports. **Do not run these editions' networks simultaneously.**

## Standard `book` topology

Ten nodes, configured to use local addresses on `127.0.0.1`:

| Nodes | Role | ORPort | ControlPort | Other |
| --- | --- | --- | --- | --- |
| `000a`–`002a` | Directory authorities and relays | 5100–5102 | 8000–8002 | DirPort 7100–7102 |
| `003r`–`005r` | Middle relays | 5103–5105 | 8003–8005 | — |
| `006e`, `007e` | Exit relays restricted to private local destinations | 5106, 5107 | 8006, 8007 | Destination range `127.0.0.0/8` |
| `008c` | Client | — | 8008 | SocksPort 9008 |
| `009h` | Onion service | — | 8009 | Virtual port 5858 to `127.0.0.1:4747` |

Chutney's per-node convention is ORPort `5100+n` **for relay roles**, ControlPort `8000+n` and SocksPort `9000+n` **for clients**; a client or onion-service node does not thereby acquire a relay ORPort. The Italian reference describes authority voting at 20-second intervals, but **actual bootstrap and consensus timing require runtime verification**.

## If something goes wrong

- **`address already in use`**: a process or a second edition's network may occupy a host port (including local HTTP servers at 4747 or 8080). Stop the conflicting process before retrying. `--network host` does not prevent port collisions.
- **Nodes appear active but do not respond**: stale `pid` files can remain after an abnormal shutdown. Check the Chutney state before restarting; the Italian root `make riavvia` is not suitable for EN.
- **A circuit does not build on the first attempt**: a small test network can show transient failures. A repeated reproducible failure requires diagnosis; re-running is not proof of success.
- **A client fails to start**: Chutney may require its second startup phase (`CHUTNEY_LAUNCH_PHASE=2`). Inspect the client logs and topology rather than assuming `make start` has succeeded.
- **`make start` fails midway**: the Makefile does not roll back a partially created container/network automatically. Inspect the state and logs before cleanup or retry; `make clean` irreversibly removes generated node identities.

## Safety

Some scripts deliberately emit unusual traffic, malformed Tor cells or controlled probes. **Only run them against the private, disposable Chutney lab.** Do not run them on public relays or live services: this can disrupt others and may be unlawful (Chapter 25). The `net/` tree contains private laboratory keys: **never publish it**. The outputs in the book come from reference runs; your run may differ in its details.
