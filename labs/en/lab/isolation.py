# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratory 11 (Chapter 18): observe stream isolation with Stem.
import re, subprocess, time
from stem import StreamStatus
from stem.control import Controller, EventType

DESTINATION = "127.0.0.1:8080"
SOCKS = "127.0.0.1:9008"

assigned, warnings = [], []


def on_stream(ev):
    # Only streams to our destination: tor continuously opens its own streams
    # (directory requests), which would distort the count.
    if ev.status == StreamStatus.SUCCEEDED and ev.target == DESTINATION:
        assigned.append((ev.id, ev.circ_id, ev.target))


def tunnel(c, circ: str) -> str:
    """A circuit can belong to a Conflux set (two linked legs; Chapter 31);\n    in that case isolation applies to the set, not to an individual leg."""
    for row in c.get_info("circuit-status").splitlines():
        if row.split(" ", 1)[0] == circ:
            r = re.search(r"CONFLUX_ID=(\w+)", row)
            return f"conflux {r.group(1)[:8]}" if r else f"circuit {circ}"
    return f"circuit {circ}"


def wait_for_tunnel(c, seconds=30):
    """Wait until tor has rebuilt at least one complete Conflux set (two legs)."""
    for _ in range(seconds * 2):
        sets = re.findall(r"^\d+ BUILT .*CONFLUX_ID=(\w+)", c.get_info("circuit-status"), re.M)
        if any(sets.count(x) >= 2 for x in sets):
            return
        time.sleep(0.5)


def request(c, credentials=None):
    """Perform a request and return the circuit tor used for it.
    Use the final event: if one attempt fails, tor retries the stream on another
    circuit and emits another SUCCEEDED event."""
    assigned.clear()
    cmd = ["curl", "--noproxy", "", "-s", "-o", "/dev/null", "--socks5-hostname", SOCKS, f"http://{DESTINATION}/"]
    if credentials:
        cmd[1:1] = ["--proxy-user", credentials]
    subprocess.run(cmd, check=True)
    for _ in range(20):
        time.sleep(0.5)
        if assigned:
            break
    if not assigned:
        return "?", []
    circ = assigned[-1][1]
    return tunnel(c, circ), [x[1] for x in c.get_circuit(circ).path]


def newnym(c, announce=False):
    """NEWNYM is honored at most once every 10 seconds (MAX_SIGNEWNYM_RATE in
    src/core/mainloop/mainloop.c); an earlier request is delayed and logged.
    Wait until it has actually taken effect, otherwise it could occur midway through the tests."""
    warnings.clear()
    c.signal("NEWNYM")
    time.sleep(2)
    for m in list(warnings):
        r = re.search(r"Rate limiting NEWNYM request: delaying by (\d+) second", m)
        if r:
            if announce:
                print(f"(NEWNYM delayed by {r.group(1)} s)")
            time.sleep(int(r.group(1)) + 1)


with Controller.from_port(port=8008) as c:
    c.authenticate()
    c.add_event_listener(on_stream, EventType.STREAM)
    c.add_event_listener(lambda ev: warnings.append(ev.message), EventType.NOTICE)
    newnym(c)                     # start from new circuits, with no pending NEWNYM
    wait_for_tunnel(c)             # and with at least one tunnel already ready; otherwise the first
                                  # requests may land on newly built, different tunnels
    for credentials in ["site-a.example:x1", "site-a.example:x1", "site-b.example:x2", None]:
        circ, path = request(c, credentials)
        name = credentials.split(":")[0] if credentials else "-"
        print(f"credentials {name:15s} -> {circ:22s} {path}")
    newnym(c, announce=True)
    circ, _ = request(c, "site-a.example:x1")
    print(f"after NEWNYM, site-a.example  -> {circ}")
