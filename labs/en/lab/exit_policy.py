# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratory 14 (Chapter 22): an exit-policy rule and its consequences.
# Add to test006e a rejection for one port, before the rules that accept
# 127.0.0.0/8, then test three destinations. Always restore the original torrc.
import http.server
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

from torlab.cells import RelayCommand, RelayMessage
from torlab.circuit import CircuitError, build
from torlab.laboratory import relay
from torlab.stream import END_REASONS, begin_body

LAB = Path(__file__).resolve().parent
EXIT = LAB / "net" / "nodes" / "006e"
CONTAINER = "torbook-network"
OPEN_PORT, BLOCKED_PORT, NO_SERVER_PORT = 8081, 8080, 9999


class FixedResponseHandler(http.server.BaseHTTPRequestHandler):
    """Return a fixed response instead of exposing local working files."""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = "Private Tor exit-policy lab\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass



def hup():
    # Read the exact PID of 006e; never match an arbitrary process by substring.
    command = (
        'pid=$(cat /lab/net/nodes/006e/pid) || exit 1; '
        'case "$pid" in ""|*[!0-9]*) exit 1;; esac; '
        'args=$(ps -p "$pid" -o args=) || exit 1; '
        'case "$args" in *006e/torrc*) kill -HUP "$pid";; *) exit 1;; esac'
    )
    subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", command],
                   check=True, timeout=15)


def test_destination(port: int) -> str:
    """Request a local destination through the private network's three-hop circuit."""
    if port not in (OPEN_PORT, BLOCKED_PORT, NO_SERVER_PORT):
        raise ValueError("Destination must be one of this lab's three ports")
    circ = build([relay("003r"), relay("005r"), relay("006e")])
    try:
        circ.send(RelayMessage(RelayCommand.BEGIN, 1, begin_body("127.0.0.1", port)))
        try:
            _, response = circ.receive()
        except CircuitError as error:
            return str(error)
        if response.command == RelayCommand.CONNECTED:
            return "CONNECTED"
        if response.command != RelayCommand.END:
            raise RuntimeError("Unexpected response" + f": {response.command}")
        reason = response.data[0] if response.data else 1
        suffix = ""
        if reason == 4 and len(response.data) == 9:
            ip = ".".join(str(b) for b in response.data[1:5])
            suffix = f" address={ip} TTL={int.from_bytes(response.data[5:9], 'big')}"
        return f"END reason={END_REASONS.get(reason, reason)}{suffix}"
    finally:
        circ.channel.sock.close()


def main():
    # Never run the negative case if another process is listening on its port.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.settimeout(0.25)
        if check.connect_ex(("127.0.0.1", 9999)) == 0:
            raise RuntimeError("Port 9999 is listening; the negative test would be invalid")
    torrc = EXIT / "torrc"
    original = torrc.read_text()
    rule = "ExitPolicy reject 127.0.0.1:8080"
    if re.search(r"(?m)^\s*" + re.escape(rule) + r"\s*$", original):
        raise RuntimeError("The reject rule is already present")
    match = re.search(r"(?m)^ExitPolicy\s+", original)
    if match is None:
        raise RuntimeError("No ExitPolicy directive in 006e's torrc")
    # Use direct slicing to avoid a regex replacement backreference/escape bug.
    updated = original[:match.start()] + rule + "\n" + original[match.start():]
    servers = []
    modified = False
    try:
        for port in (8081, 8080):
            try:
                server = http.server.ThreadingHTTPServer(
                    ("127.0.0.1", port), FixedResponseHandler)
            except OSError as exc:
                if port == 8081:
                    raise RuntimeError("Port 8081 is in use; the positive test requires a free port") from exc
                # Port 8080 may already belong to a local test HTTP server.
                continue
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        try:
            # Mark before write: even an interrupted write requires restoration.
            modified = True
            torrc.write_text(updated)
            hup()
            time.sleep(3)
            results = {}
            for port in (8080, 8081, 9999):
                results[port] = test_destination(port)
                print(f"127.0.0.1:{port} -> {results[port]}")
            valid = (results[8080].startswith("END reason=EXITPOLICY")
                     and results[8081] == "CONNECTED"
                     and results[9999] in ("END reason=MISC",
                                            "END reason=CONNECTREFUSED"))
            if not valid:
                raise RuntimeError("Lab outcomes differ from expected categories")
        finally:
            if modified:
                torrc.write_text(original)
                try:
                    hup()
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    raise RuntimeError("Failed to reload original torrc: inspect node 006e immediately") from exc
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
