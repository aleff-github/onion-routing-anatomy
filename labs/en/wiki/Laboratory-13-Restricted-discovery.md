# Laboratory 13 — An Onion Service with Restricted Discovery

| | |
|---|---|
| **Chapter** | 21 — Operating an Onion Service |
| **Requires network?** | Yes, the book's private network only |
| **Prerequisites** | Laboratory 8; Docker, Python, `cryptography` |
| **Time** | 1–2 hours |
| **File** | `labs/en/lab/restricted_discovery.py` |

## What This Demonstrates

A v3 onion service can use **X25519 client authorization** to protect its descriptor's inner layer. Clients without the correct private key cannot decrypt that layer to discover the introduction points, and generally cannot connect to the service. The descriptor itself may still be downloaded from an HSDir: **retrieval does not imply successful decryption**. Restricted discovery acts before any application-level login.

**Crucial safety condition:** Tor enables client authorization only if it successfully loads at least one valid `.auth` file. An **empty** `authorized_clients` directory is **not a security mechanism**: with no authorization active, the service may be accessible to anyone knowing its address. An earlier `400 Invalid HS descriptor` error was a version-specific lab observation, **not a universal guarantee**. Never rely on such an error to protect a real service.

## Preparation

Run from the repository root, only against a disposable private laboratory network. Language editions share host ports; do not start them simultaneously. Build the image before the first run and start a local HTTP server:

```bash
# First run only: make -C labs/en/lab image
make -C labs/en/lab start
python3 -m http.server 8080 --bind 127.0.0.1 &
export PYTHONPATH=labs/en/code
```

The script creates a **second** onion service under node `009h/restricted_service`, leaving the normal service unchanged. It now **refuses to overwrite** existing `restricted_service` or `onion_auth` directories or authorization directives. It does not delete possible leftovers on startup. New key files receive restricted permissions; if the final Tor reload fails, generated files are retained for manual inspection.

## Run the Experiment

```bash
python3 labs/en/lab/restricted_discovery.py
```

## Example Output (Varies Between Runs)

```text
restricted service: 4stlyhm3pkptxitznaip66qf3tnuhujabwq6louhibhds7lwk7qcoeyd.onion
without key: 000
with key: 200
```

The newly generated onion address, timing and HTTP observations can vary. **`000` is a curl placeholder when no HTTP response code is available, not proof that authentication blocked access.** A missing HTTP server, SOCKS failure, timeout or bootstrap issue can produce it too. **`200`** shows that the authorized attempt reached the test HTTP server, but does not independently establish why the unauthenticated attempt failed.

## How It Works

1. Generate a fresh **X25519** key pair and add a second temporary onion service on `009h`.
2. Before reloading Tor, place its **public** key in `<HiddenServiceDir>/authorized_clients/alice.auth` as `descriptor:x25519:<base32-public-key>`. At least one valid, readable `.auth` file must be loaded.
3. Configure the client `008c` `ClientOnionAuthDir`. For the authorized attempt, add the **private** key to `alice.auth_private` in the format `<address-without-.onion>:descriptor:x25519:<base32-private-key>`.
4. Send HUP only to the intended Tor process by checking the node PID and its command line first. Test the URL without the credential, then with it; requests use the lab SOCKS proxy and explicitly disable `NO_PROXY` bypass.
5. Restore both original `torrc` files in `finally`, reload Tor and only then remove directories **created during this run**. Abrupt termination such as `SIGKILL` may bypass `finally`; inspect the test network manually before another attempt.

The script rejects an unexpected result other than `000` without a key and `200` with one. These are **teaching checks**, not a complete proof of descriptor security or network correctness.

## Known Problems and Recovery

| Symptom | What to check |
|---|---|
| Both requests display `000` | Verify local HTTP service on 8080, bootstrap, descriptor publication, SOCKS and Tor logs. |
| Client exits after `ClientOnionAuthDir` | The directive must use a path **inside the container**, derived from the node's `DataDirectory`. |
| Authorization directories already exist | The script now refuses to proceed. Inspect `torrc`, `restricted_service` and `onion_auth` in the **disposable** network; do not delete keys blindly. |
| `400 Invalid HS descriptor` or unauthorized access unexpectedly succeeds | Verify that Tor actually loaded at least one valid `.auth` file. An empty directory does not imply enforced authorization. |
| HUP or restore fails | Inspect the exact node PID, `torrc` and retained temporary keys. Avoid broad `pkill -HUP -f` or destructive cleanup commands. |

## Automated Verification and Limits

The **Italian** `scripts/verify_labs.py::lab13` checks printed `000` / `200` results. It does not determine the root cause of a missing HTTP response, nor verify every cryptographic step. The Python program exits with an error when the observed values differ. `make -C labs/en/lab verify` checks Chutney networking, not the Italian `lab13` verification.

References: [Tor Project — Client Authorization](https://community.torproject.org/onion-services/advanced/client-auth/) and [Tor Specifications — Restricted Discovery](https://spec.torproject.org/rend-spec/restricted-discovery.html).
