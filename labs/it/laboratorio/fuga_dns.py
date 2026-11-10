# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 18 — diagnostica SOCKS in una rete Tor privata.

Si usa soltanto localhost tramite il client 008c della rete privata Chutney.
Gli avvisi SOCKS NON dimostrano che si sia verificata una fuga DNS.

Con --socks5-hostname il nome lo risolve l'exit, con il resolver della rete privata
(dns_locale.py, solo 127.0.0.1:5300): resta attivo solo durante la prova e le domande
che riceve vengono stampate su stderr, a riprova che la risoluzione è avvenuta all'exit.
"""
from __future__ import annotations

import http.server
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

from dns_locale import ResolverLocale

URL = "http://localhost:8080/"
SOCKS = "127.0.0.1:9008"
CONTROL_PORT = 8008
PRIVATE_CLIENT = Path("/lab/net/nodes/008c")
DNS_CONF = Path("/lab/dns_locale.conf")


def riattiva_resolver_degli_exit() -> None:
    """Fa rileggere agli exit il resolver, ora attivo.

    Se un exit ha già provato a risolvere un nome a resolver spento, libevent lo segna
    come guasto e ritenta a intervalli crescenti. Con SIGHUP tor rilegge
    ServerDNSResolvConfFile solo se il file è cambiato (dns.c, configure_nameservers):
    se ne aggiorna la data, non il contenuto, e si manda SIGHUP ai soli exit.
    """
    os.utime(DNS_CONF)
    exit_ = [t.parent.name for t in sorted(PRIVATE_CLIENT.parent.glob("*/torrc"))
             if re.search(r"^ExitRelay 1$", t.read_text(), re.M)]
    if not exit_:
        raise RuntimeError("nessun exit nella rete privata")
    for nome in exit_:
        subprocess.run(["pkill", "-HUP", "-f", f"{nome}/torrc"], check=True)
    time.sleep(2)


class LocalResponse(http.server.BaseHTTPRequestHandler):
    """Risponde con testo fisso, senza esporre file di /lab o altre directory."""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = "Laboratorio Tor privato".encode("utf-8") + b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def check_environment() -> None:
    if not PRIVATE_CLIENT.is_dir() or not Path("/lab/chutney/networks/libro").is_file():
        raise RuntimeError("Eseguire solo nella rete privata Chutney")


def request(option: str) -> tuple[str, int]:
    if option not in ("--socks5", "--socks5-hostname"):
        raise ValueError("Opzione SOCKS non consentita nel laboratorio")
    result = subprocess.run(
        ["curl", "-4", "--silent", "--show-error", "--output", "/dev/null",
         "--write-out", "%{http_code}", "--max-time", "25", "--noproxy", "",
         option, SOCKS, URL],
        capture_output=True, text=True, timeout=30, check=False)
    status = result.stdout.strip()
    return (status if re.fullmatch(r"[0-9]{3}", status) else "000",
            result.returncode)


def restore_options(controller, previous: dict[str, str | None]) -> None:
    for name, value in previous.items():
        if value is None:
            controller.reset_conf(name)
        else:
            controller.set_conf(name, value)


def run_cases(controller, notice_type, warn_type) -> bool:
    messages: list[str] = []
    def record(event):
        messages.append(event.message)
    previous = {name: controller.get_conf(name, default=None)
                for name in ("TestSocks", "SafeSocks")}
    listening = False
    try:
        controller.add_event_listener(record, notice_type, warn_type)
        listening = True
        controller.set_options({"TestSocks": "1", "SafeSocks": "0"})
        all_ok = True
        for opt, marker in (("--socks5", "IP address"),
                            ("--socks5-hostname", "DNS resolution")):
            start = len(messages)
            status, returncode = request(opt)
            time.sleep(1)
            notification = next((m for m in messages[start:]
                                 if marker.casefold() in m.casefold()), "")
            print(f"{opt:18s} HTTP {status}  tor: "
                  f"{(notification or 'Nessun avviso da Tor')[:110]}")
            all_ok &= (status == "200" and returncode == 0
                       and bool(notification))
        controller.set_conf("SafeSocks", "1")
        denied, code = request("--socks5")
        print(f"{'--socks5 SafeSocks':18s} HTTP {denied}")
        all_ok &= (denied == "000" and code != 0)
        return bool(all_ok)
    finally:
        try:
            restore_options(controller, previous)
        finally:
            if listening:
                controller.remove_event_listener(record)


def main() -> int:
    check_environment()
    # Importazione differita di Stem: la lettura del codice non richiede Tor.
    from stem.control import Controller, EventType
    # Un server sulla 8080, se non ce n'è già uno: make verifica-lab tiene aperto il proprio
    # per tutta l'esecuzione e, con --network host, condivide il loopback con il container.
    server = thread = None
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), LocalResponse)
    except OSError:
        pass
    if server is not None:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    try:
        with ResolverLocale() as dns, \
                Controller.from_port(address="127.0.0.1", port=CONTROL_PORT) as ctrl:
            ctrl.authenticate()
            riattiva_resolver_degli_exit()
            passed = run_cases(ctrl, EventType.NOTICE, EventType.WARN)
            for domanda in dns.domande:
                print(f"dns locale: {domanda}", file=sys.stderr)
        if not passed:
            raise RuntimeError("La prova DNS/SOCKS non ha superato tutti i controlli")
        return 0
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    raise SystemExit(main())
