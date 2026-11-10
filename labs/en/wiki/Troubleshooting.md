# Troubleshooting

Every entry on this page describes a problem actually encountered while writing the book, together with the cause identified at the time. These are historical incidents from the reference edition, **not a guarantee that the same symptoms have the same cause in every release**. The translated environment uses Docker `--network host` and shares port ranges with the other language editions.

## The network will not start

**`docker: Error response from daemon: Conflict. The container name "torbook-network" is already in use`**  
The container may exist even when stopped. First check `docker ps -a` and confirm `torbook-network` belongs to your disposable laboratory, then run `make -C labs/en/lab stop`. EN/RU/ZH-CN share this container name and image name; do not remove another edition's running work.

**Bootstrap does not finish; nodes remain at 5%**  
Port conflicts, unavailable authorities or stale processes are possible causes. **Do not run `pkill -x tor` indiscriminately**: it terminates all processes with that name in the selected container. Start with non-destructive checks:

```bash
docker ps -a
ss -ltnp | grep -E ':(510[0-9]|710[0-9]|800[0-9]|900[0-9])' || true
```

After confirming that `torbook-network` is your disposable EN laboratory, stop it using `make -C labs/en/lab stop` and restart with `make -C labs/en/lab start`. Broad `pkill -f "tor -f"` matching can include the invoking shell, while even `pkill -x tor` may stop unrelated Tor instances inside that container.

**Nodes appear to be running but do not respond**  
Stale `pid` files may remain after an abrupt shutdown. **The root Italian `make riavvia` target is not an EN restart command**; it targets the separate `torlibro-rete` container and cannot recover the EN environment. First inspect `labs/en/lab/net/`, preserve anything needed, and if a fresh network is acceptable use:

```bash
make -C labs/en/lab clean
make -C labs/en/lab start
```

**Destructive:** `clean` deletes the generated network, keys and onion identities. Chutney starts clients and onion services in a second phase (`CHUTNEY_LAUNCH_PHASE=2`); the documented `start` target orchestrates bootstrap.

**`chutney verify` fails with `Address already in use`**  
Another program may occupy a laboratory port; examine both test-server ports and ORPort/ControlPort/SOCKS ranges before deciding which process to stop.

```bash
ss -ltnp | grep -E ':(8080|4747|9008)'
```

## Distinguishing offline tests from network verification

`PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test` tests Python modules and stored fixtures; **it does not start the private network or its HTTP server on 8080**. `make -C labs/en/lab verify` instead invokes Chutney verification on an already-running topology. The root Italian `make verifica-lab` uses the Italian `lab/` network and checks additional live experiments: **it is not an EN suite**. A `cannot bind port 8080` error belongs to a **live laboratory/server** that attempts to open that port; identify its owner before restarting the experiment.

**Every network laboratory fails**  
For a **live** experiment, check `make -C labs/en/lab status` and then `labs/en/lab/net/nodes/000a/notice.log` and client `008c/notice.log`, if present. These files are not required by the offline pytest suite.

**A laboratory fails once and passes on retry**  
In a **live** circuit-building exercise, transient failures may occur in this small topology. A `CREATE2 rejected (command 4)` report may indicate a `DESTROY` response; preserve logs and inspect the reason rather than treating a successful retry as proof that everything is correct. Offline fixture tests should be reproducible; a flaky unit test still deserves investigation.

**Only Laboratories 7, 15, and 19 fail their numerical checks**  
The **Italian root verifier**, not the English pytest suite, compares the book's historical figures against the 23 September 2026 consensus under `fonti/collector/`. It reports unavailable data as **skipped rather than passed**. English simulations can be run separately after downloading the appropriate consensus using `make -C labs/en data`; the standalone pytest suite does not reproduce the published 18.4% reference by default.

## Individual laboratories

**The onion service stops responding; logs report `400 Invalid HS descriptor`**  
The earlier laboratory observed an empty `authorized_clients` directory, but `400 Invalid HS descriptor` is **not** a universal diagnosis. Importantly, an empty directory **does not enable client authorization**: Tor needs to load at least one valid `.auth` file containing `descriptor:x25519:<base32-public-key>`. Without enabled authorization, a service might be accessible to anyone who knows its address. If [Laboratory 13](Laboratory-13-Restricted-discovery.md) was interrupted, start with **read-only inspection**:

```bash
ls -la labs/en/lab/net/nodes/009h/restricted_service/authorized_clients/
grep -nE 'HiddenServiceDir|HiddenServicePort' labs/en/lab/net/nodes/009h/torrc
```

The script targets HUP to the **verified node PID**, attempts to restore the original `torrc` files and retains keys if restoration cannot be confirmed. **Do not** use the obsolete `pkill -HUP -f 009h/torrc` or delete keys without first inspecting the state. If necessary, reset only the **confirmed disposable network** with `clean` and `start`, recognizing that all generated identities will be lost. Never use this recovery procedure for a real onion service.

**The laboratory client exits after a torrc change**  
A configuration option such as `ClientOnionAuthDir` or `HiddenServiceDir` contains a **host** path, but tor reads it **inside** the container. This triggers a configuration error. Derive container paths from the node's `DataDirectory`.

**An exit responds with `END TORPROTOCOL` to every request**  
You are using a **single-hop** circuit. An exit refuses to forward traffic from such a circuit, which would effectively make it an open proxy. Build a three-hop circuit.

**`LookupError: no microdescriptor for 003r`**  
The client has not downloaded the microdescriptors yet. Allow about one minute after startup.

**`the relay has a different identity from the expected one`, but the port is correct**  
You regenerated the network and consequently generated new keys. Each `make -C labs/en/lab clean` changes all node identities. Read `fingerprint-ed25519` again.

**The pcap is empty, or `tshark` cannot decrypt anything**  
Possible causes include capture starting after the traffic, insufficient `tcpdump` permissions, or `SSLKEYLOGFILE` being configured **after** a TLS socket was created. There is no verified frequency ranking for these causes, and **not every TLS implementation or Tor process exports the session secrets** needed for decryption.

## Restore the original state

The laboratory network is disposable. If its state becomes difficult to diagnose, starting fresh is often simplest:

```bash
make -C labs/en/lab clean
make -C labs/en/lab start
make -C labs/en/lab verify        # verify the active Chutney topology; check actual output
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test   # run offline fixture tests
```

**Warning:** `clean` deletes the generated data and test keys in `labs/en/lab/net/`. Confirm that the directory contains only your disposable laboratory state before using it. Initialization time and test counts are not guaranteed. Inspect the directory for generated keys, onion identities and any results you might need before deleting it.

## If your problem is not listed

Each node has a log at `labs/en/lab/net/nodes/<node>/notice.log`; the client's log is often particularly useful. For more detail, read `info.log` if the node is configured to write it.

When an experimental result does not match expectations, the most effective method is often to identify an intermediate checkpoint and compare your results with those of a reference implementation. The `tor` client running inside the laboratory has a control port, responds to `GETINFO`, and implements almost everything our experimental client attempts—while being far more thoroughly tested.
