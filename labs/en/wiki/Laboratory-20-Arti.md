# Laboratory 20 — Arti on the Private Network

| | |
|---|---|
| **Chapter** | 30 — Arti, the Rust Rewrite |
| **Requires network?** | Yes, plus Rust to build Arti |
| **Prerequisites** | Running laboratory network; `cargo` |
| **Time** | About 1 hour plus compilation time |
| **File** | `labs/en/lab/arti_config.py` |

## What This Demonstrates

The book's private network is not “a network for the C implementation of tor”; it is a Tor protocol network. A separate implementation can join it, download directory information, build circuits, and send traffic through relays written in C without those relays needing to know which client implementation is on the other end.

This is strong evidence that the formats studied throughout the book are interoperable protocol formats rather than implementation-specific conventions.

## Preparation

Build the historically pinned Arti 2.6.0 release **for reproducing this controlled private-network experiment**, not for ordinary use on the public Tor network. Later Arti releases (including 2.7.0 in October 2026) contain security fixes. The source is hosted by the Tor Project:

```bash
mkdir -p labs/en/vendor
git clone https://gitlab.torproject.org/tpo/core/arti.git labs/en/vendor/arti
git -C labs/en/vendor/arti checkout arti-v2.6.0
(cd labs/en/vendor/arti && cargo build --release -p arti --locked)
```

Generate a configuration for the private network:

```bash
export PYTHONPATH=labs/en/code
python3 labs/en/lab/arti_config.py
```

The script reads authority identities and ports from the private-network node files and writes `labs/en/lab/net/arti/arti.toml`. It mirrors the choices needed for the laboratory environment: private authorities and fallbacks, local addresses, no subnet-diversity constraint because every node is on loopback, and the shortened HSDir interval.

## Run the Experiment

Run these commands from the repository root in a POSIX shell after starting the private laboratory network with `make -C labs/en/lab start` (do not start it again if it is already running). The test checks **both** the HTTP status and a fixed response body, so a pre-existing service on port 8080 cannot be mistaken for the laboratory server. The server does not expose the current working directory.

```sh
(
set -eu
ARTI_BIN="labs/en/vendor/arti/target/release/arti"
ARTI_CFG="labs/en/lab/net/arti/arti.toml"
ARTI_LOG="labs/en/lab/net/arti/arti.log"
HTTP_LOG="labs/en/lab/net/arti/http.log"
ARTI_PID=
HTTP_PID=
BODY_FILE=

cleanup() {
  if [ -n "$HTTP_PID" ]; then
    kill "$HTTP_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
  fi
  if [ -n "$ARTI_PID" ]; then
    kill "$ARTI_PID" 2>/dev/null || true
    wait "$ARTI_PID" 2>/dev/null || true
  fi
  if [ -n "$BODY_FILE" ]; then rm -f "$BODY_FILE"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[ -x "$ARTI_BIN" ] && [ -f "$ARTI_CFG" ] || {
  echo "Arti binary or private configuration missing" >&2
  exit 1
}
: > "$ARTI_LOG"
"$ARTI_BIN" proxy -c "$ARTI_CFG" > "$ARTI_LOG" 2>&1 &
ARTI_PID=$!

# Wait for this Arti process to bootstrap
ready=0
n=0
while [ "$n" -lt 60 ]; do
  if grep -q "proxy now functional" "$ARTI_LOG" && kill -0 "$ARTI_PID" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$ARTI_PID" 2>/dev/null; then
    echo "Arti exited before bootstrap; inspect $ARTI_LOG" >&2
    exit 1
  fi
  n=$((n + 1))
  sleep 2
done
[ "$ready" -eq 1 ] || {
  echo "Arti bootstrap not ready; inspect $ARTI_LOG" >&2
  exit 1
}

# Local HTTP server: serves a fixed response at / only
python3 -u - > "$HTTP_LOG" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = b"arti-private-lab-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
PY
HTTP_PID=$!
sleep 1
kill -0 "$HTTP_PID" 2>/dev/null || {
  echo "Local HTTP server failed; inspect $HTTP_LOG" >&2
  exit 1
}

BODY_FILE=$(mktemp)
HTTP_CODE=$(curl --fail --silent --show-error --max-time 30 \
  --noproxy "" --socks5-hostname 127.0.0.1:9150 \
  -o "$BODY_FILE" -w '%{http_code}' http://127.0.0.1:8080/)
[ "$HTTP_CODE" = "200" ] && [ "$(cat "$BODY_FILE")" = "arti-private-lab-ok" ] || {
  echo "Unexpected HTTP response from private lab" >&2
  exit 1
}
printf '%s\n' "$HTTP_CODE"
)
```

The snippet truncates any stale log, checks that this Arti process remains alive, fails if port 8080 is already occupied, and terminates **only the processes it started** even on handled errors or signals. Do not use `pkill` to stop unrelated instances. A `200` result is accepted **only together with** the fixed `arti-private-lab-ok` response body and a zero curl exit status. The test assumes the **private-network exits** can reach the local server, not that public Tor exits permit loopback traffic.

## Reference Output

```
2026-09-24T16:05:45Z  INFO arti::subcommands::proxy: Sufficiently bootstrapped; proxy now functional.
200
```

How to interpret it:

- Arti downloaded and verified directory information from the private authorities, bootstrapped, built a circuit and successfully proxied an HTTP request through the same relay network. Relay nodes do not need implementation-specific knowledge of the client.
- An empty `--noproxy ""` forces the loopback request through SOCKS, despite any `NO_PROXY`/`no_proxy` settings. The log and HTTP result shown are historical examples, not newly executed tests.
- Arti's default SOCKS port in this setup is **9150**, matching Tor Browser conventions rather than the standalone tor default of 9050.

## What Differs from tor

Arti uses TOML configuration rather than `torrc`. Private authority entries need fields such as `rsa_identity`, `ed_identity`, and `orports`, explicitly carrying both legacy and Ed25519 identities.

Chapter 30 discusses Arti's supported functionality and intentionally missing roles in greater detail, including the fact that relay operation remains a different implementation scope.

One source correction is worth preserving: an Arti `Compatibility.md` version table was found to be offset by one for `FlowCtrl` compared with torspec. The specification and the observed public consensus (`FlowCtrl=1-2`) identify 1 as `AUTH_SENDME` and 2 as congestion control. When implementation documentation and the protocol specification conflict, the protocol specification and network data deserve direct verification.

## Automated Verification

The Italian reference checker `scripts/verify_labs.py::lab20` is **not the verifier for this localized guide**. It expects the root-level binary `fonti/arti/target/release/arti` and runs `lab/arti_config.py`, whereas this guide uses `labs/en/...`. A missing root-level binary is reported as **skipped, not passed**.

## Known Problems

| Symptom | Cause |
|---|---|
| `Lab 20: Arti binary not found; laboratory skipped` | `labs/en/vendor/arti/target/release/arti` is missing. |
| Bootstrap never completes | The private network may be stopped, or `arti.toml` was generated before a later network regeneration. Run `arti_config.py` again. |
| `Permission denied` for state directories | Arti requires restrictive permissions on its state. Remove only the disposable laboratory state under `labs/en/lab/net/arti/state` and retry. |
| `pkill -f "arti proxy"` or `pkill -x arti` stops unrelated sessions | Avoid process-name termination. This snippet captures the PIDs it starts and cleans them up with `trap`. |
