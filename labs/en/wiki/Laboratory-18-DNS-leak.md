# Laboratory 18 — tor Detects a DNS-Leak Warning Sign

| | |
|---|---|
| **Chapter** | 28 — User Operational Mistakes |
| **Requires network?** | Yes |
| **Prerequisites** | Running laboratory network |
| **Time** | About 1 hour |
| **File** | `labs/en/lab/dns_leak.py` |

## What This Demonstrates

One of the easiest mistakes when manually configuring applications for Tor is to let the **application resolve hostnames locally** instead of handing the hostname to tor. The later TCP connection may still travel through Tor, creating the impression that everything is protected, while name resolution could already have exposed a domain outside Tor; a query is not inevitable and need not be plaintext.

The laboratory also demonstrates that tor can **detect the warning sign** when configured to do so.

## Preparation

Run from the repository root; build the image first with `make -C labs/en/lab image` if necessary. Do not run language networks simultaneously because they share host ports.

```bash
make -C labs/en/lab start
```

The script starts a fixed-response local HTTP server that never serves directory contents and runs inside the container because it uses `stem` to receive warnings from the client's ControlPort:

```bash
docker exec -w /tmp torbook-network python3 /lab/dns_leak.py
```

## Example Output (Varies Between Runs)

The script prints **three lines**, one per test. Tor's messages are truncated to 110 characters and may vary across versions. These are **schematic excerpts**, not an exact guaranteed transcript:

```text
--socks5           HTTP 200  tor: ... only an IP address ...
--socks5-hostname  HTTP 200  tor: ... DNS resolution itself if necessary ...
--socks5 SafeSocks HTTP 000
```

How to interpret it:

- **`--socks5`** causes curl to resolve the name locally and pass tor **only an IP address**. The HTTP request still succeeds in this controlled example, which is precisely why the mistake can go unnoticed. `TestSocks 1`, enabled temporarily by the script, causes tor to report an IP-only request; this alone is not proof that DNS leaked.
- **`--socks5-hostname`** passes the **hostname** through SOCKS so resolution can be performed by the exit side. This is the intended form.
- With **`SafeSocks 1`**, tor rejects the IP-only request instead of merely warning. curl reports `000` because no HTTP connection is established.

A few characters in a command-line option can therefore change where name resolution occurs. This is one reason ordinary users should prefer Tor Browser over manually configuring arbitrary applications.

> **Important limitation.** The laboratory deliberately uses `localhost`, which resolves to loopback without querying an external DNS resolver. No real DNS query leaves the machine during this experiment. What it demonstrates is the mechanism: with `--socks5`, the application resolves before talking to tor and tor receives only an IP address. Replacing `localhost` with an ordinary domain could cause an external DNS query (possibly plaintext, depending on resolver settings), which this private-network experiment intentionally avoids.

## Three Relevant tor Options

| Option | Effect |
|---|---|
| `TestSocks 1` | Logs which SOCKS request form tor observed. Diagnostic only. |
| `SafeSocks 1` | Rejects requests that provide an IP address instead of a hostname. |
| `WarnUnsafeSocks` | Emits warnings; enabled by default in the source configuration. |

None of these settings can stop a DNS query that has already happened **before** the application contacts tor. They can only react to the request form tor receives. The script uses `--noproxy ''` so a `NO_PROXY` environment variable cannot bypass SOCKS for `localhost`.

**Safety and restoration.** The script serves only a fixed text response at `127.0.0.1:8080`, without exposing local directory files; it fails rather than borrowing another process's occupied port. It forces `--noproxy ''`, retains the previous `TestSocks` and `SafeSocks` values, and restores them in `finally` even if a request raises an error. It checks both HTTP status and curl's exit status and requires the corresponding Tor notices; otherwise it exits with an error. Abrupt termination can bypass `finally`. `localhost` is usually resolved by local name services, but **this script does not capture DNS packets** and cannot certify that no query was emitted.

## Automated Verification

The **Italian** `scripts/verify_labs.py::lab18` compares three exact output lines and diagnostic substrings, without checking the subprocess exit code. It may falsely reject changed Tor wording. This listing is not the outcome of a new run.

## Known Problems

| Symptom | Cause |
|---|---|
| No warning appears | The script may have failed to enable `TestSocks` through `SETCONF` on the ControlPort. |
| The third test still returns `200` | `SafeSocks` was not successfully applied. |
| All three tests return `HTTP 000` | The private-network connection or the script's local HTTP server may have failed. |
