# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio 14 (capitolo 22): una regola di uscita e le sue conseguenze.
# Aggiunge a test006e un rifiuto per una sola porta, prima delle regole che accettano
# 127.0.0.0/8, e prova tre destinazioni. Ripristina sempre il torrc di partenza.
import http.server
import re
import subprocess
import threading
import time
from pathlib import Path

from torlab.celle import ComandoRelay, MessaggioRelay
from torlab.circuito import ErroreCircuito, costruisci
from torlab.laboratorio import relay
from torlab.stream import MOTIVI_END, corpo_begin

LAB = Path(__file__).resolve().parent
EXIT = LAB / "net" / "nodes" / "006e"
CONTAINER = "torlibro-rete"
APERTA, CHIUSA, SENZA_SERVER = 8081, 8080, 9999


class RispostaFissa(http.server.BaseHTTPRequestHandler):
    """Restituisce testo fisso senza esporre file locali."""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = "Laboratorio privato Tor\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass



def hup():
    subprocess.run(["docker", "exec", CONTAINER, "pkill", "-HUP", "-f", "006e/torrc"], check=True)


def prova(porta: int) -> str:
    """Apre uno stream verso 127.0.0.1:porta attraverso un circuito di tre salti.
    Un exit rifiuta di uscire da un circuito di un solo salto (END TORPROTOCOL)."""
    circ = costruisci([relay("003r"), relay("005r"), relay("006e")])
    circ.invia(MessaggioRelay(ComandoRelay.BEGIN, 1, corpo_begin("127.0.0.1", porta)))
    try:
        _, risposta = circ.ricevi()
    except ErroreCircuito as e:
        return str(e)
    if risposta.comando == ComandoRelay.CONNECTED:
        return "CONNECTED"
    motivo = risposta.dati[0] if risposta.dati else 0
    coda = ""
    if motivo == 4 and len(risposta.dati) >= 9:                 # indirizzo IPv4 e TTL
        ip = ".".join(str(b) for b in risposta.dati[1:5])
        coda = f" indirizzo={ip} TTL={int.from_bytes(risposta.dati[5:9], 'big')}"
    return f"END motivo={MOTIVI_END.get(motivo, motivo)}{coda}"


def main():
    serventi = []
    for porta in (APERTA, CHIUSA):
        try:                                   # un server sulla porta, se non ce n'è già uno
            s = http.server.ThreadingHTTPServer(("127.0.0.1", porta), RispostaFissa)
        except OSError:
            continue
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
        serventi.append(s)
    torrc = EXIT / "torrc"
    originale = torrc.read_text()
    # La regola va inserita PRIMA delle ExitPolicy esistenti: vince la prima che corrisponde.
    nuovo = re.sub(r"^(ExitPolicy )", f"ExitPolicy reject 127.0.0.1:{CHIUSA}\\n\\1",
                   originale, count=1, flags=re.M)
    assert nuovo != originale, "nessuna riga ExitPolicy nel torrc di 006e"
    torrc.write_text(nuovo)
    try:
        hup()
        time.sleep(3)
        for porta in (CHIUSA, APERTA, SENZA_SERVER):
            print(f"127.0.0.1:{porta} -> {prova(porta)}")
    finally:
        torrc.write_text(originale)
        hup()
        for s in serventi:
            s.shutdown()


if __name__ == "__main__":
    main()
