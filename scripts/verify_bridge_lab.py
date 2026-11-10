# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Verifica del Laboratorio 10 (capitolo 16), che richiede la rete `libro-bridge`.

Si esegue con `make verifica-lab-bridge`, che (tramite scripts/swap_bridge_network.py)
mette da parte la rete `libro`, avvia `libro-bridge`, lancia questo script e infine
ripristina e verifica la rete di prima. Usa l'ambiente canonico dell'edizione italiana:
la rete in labs/it/laboratorio/net (vedi docs/it/procedura-laboratori-dal-vivo.md).

Che cosa verifica, e soltanto quello:
- il client con bridge completa il bootstrap e ha il descrittore del bridge;
- una richiesta HTTP attraverso il bridge riceve la risposta del server locale di
  questa esecuzione (codice 200 e contenuto con un valore casuale per esecuzione);
- durante una seconda richiesta verificata, una cattura nuova sulla porta obfs4 contiene
  traffico con dati, e tshark non classifica come TLS alcun pacchetto di quella cattura.
L'ultimo punto NON dimostra in generale che obfs4 resista al rilevamento o all'active
probing: dice solo che, in questa cattura, tshark non vi riconosce TLS.

Ogni errore (processo non avviato o non terminato, timeout, file assente, vuoto o
vecchio, output di tshark incoerente) è un controllo fallito, mai un successo.
Codice di uscita: 0 solo se tutti i controlli passano.
"""
from __future__ import annotations

import hashlib
import http.server
import re
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
NODI = RADICE / "labs" / "it" / "laboratorio" / "net" / "nodes"   # stessa rete di make verifica-lab-bridge
CONTAINER = "torlibro-rete"
PORTA_WEB = 8080
DURATA_CATTURA = 15        # secondi di cattura (tcpdump si ferma da solo, con SIGINT)
ATTESA_AVVIO = 10          # secondi entro cui tcpdump deve dire "listening on"
MAGIC_PCAP = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
              b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
INTESTAZIONE_PCAP = 24     # una cattura senza pacchetti è lunga solo quanto l'intestazione


# --- esiti -------------------------------------------------------------------------

@dataclass
class Esiti:
    righe: list[tuple[str, bool, str]] = field(default_factory=list)

    def controlla(self, nome: str, condizione: bool, dettaglio: str = "") -> bool:
        ok = bool(condizione)
        self.righe.append((nome, ok, dettaglio))
        print(f"[{'OK ' if ok else 'NO!'}] {nome}" + (f" — {dettaglio}" if dettaglio else ""))
        return ok

    @property
    def tutti_ok(self) -> bool:
        return bool(self.righe) and all(ok for _, ok, _ in self.righe)


# --- BR-02: server HTTP che non espone file ----------------------------------------

class RispostaLaboratorio(http.server.BaseHTTPRequestHandler):
    """Risponde 200 con un testo fisso soltanto su "/", 404 altrove; non legge file."""

    corpo: bytes = b"Laboratorio 10\n"          # sostituito da ServerLaboratorio
    server_version = "LaboratorioTor"
    sys_version = ""

    def _rispondi(self, codice: int, corpo: bytes, con_corpo: bool = True) -> None:
        self.send_response(codice)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if con_corpo:
            self.wfile.write(corpo)

    def do_GET(self) -> None:                       # noqa: N802 (nome imposto dalla libreria)
        if self.path == "/":
            self._rispondi(200, self.corpo)
        else:
            self._rispondi(404, b"Non trovato\n")

    def do_HEAD(self) -> None:                      # noqa: N802
        if self.path == "/":
            self._rispondi(200, self.corpo, con_corpo=False)
        else:
            self._rispondi(404, b"Non trovato\n", con_corpo=False)

    def log_message(self, format, *args) -> None:  # noqa: A002 - nessun log delle richieste
        pass


class ServerLaboratorio:
    """Server HTTP su 127.0.0.1 per una sola esecuzione, chiuso sempre in uscita.

    Il contenuto include un valore casuale: una risposta con quel valore viene per forza
    da questo server, non da un altro processo rimasto sulla stessa porta.
    """

    def __init__(self, porta: int = PORTA_WEB, indirizzo: str = "127.0.0.1"):
        if indirizzo != "127.0.0.1":
            raise ValueError("il server del laboratorio ascolta solo su 127.0.0.1")
        self.nonce = secrets.token_hex(8)
        self.corpo = f"anatomia-di-tor laboratorio-10 {self.nonce}\n".encode()
        gestore = type("RispostaQuestaEsecuzione", (RispostaLaboratorio,), {"corpo": self.corpo})
        self._server = http.server.ThreadingHTTPServer((indirizzo, porta), gestore)
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def porta(self) -> int:
        return self._server.server_address[1]

    def __enter__(self) -> "ServerLaboratorio":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.chiudi()

    def chiudi(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=10)
            self._thread = None
        self._server.server_close()


# --- accesso al container (sostituibile nei test) ----------------------------------

class Container:
    """Esegue comandi nel container del laboratorio con `docker exec`."""

    def __init__(self, nome: str = CONTAINER):
        self.nome = nome

    def _base(self, utente: str | None) -> list[str]:
        return ["docker", "exec"] + (["-u", utente] if utente else []) + [self.nome]

    def esegui(self, cmd: list[str], timeout: float = 120, utente: str | None = None):
        return subprocess.run(self._base(utente) + cmd, capture_output=True, text=True, timeout=timeout)

    def avvia(self, cmd: list[str], utente: str | None = None):
        return subprocess.Popen(self._base(utente) + cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)


# --- BR-01: richiesta attraverso il bridge, verificata ------------------------------

def richiesta_attraverso_bridge(container, socks: str, porta_web: int, atteso: bytes) -> tuple[bool, str]:
    """Una richiesta HTTP dal container attraverso il proxy SOCKS del client con bridge.

    Riuscita solo se curl termina con 0, il codice è 200 e il corpo è quello di questa
    esecuzione. Nessun "|| true": un errore è un errore.
    """
    try:
        r = container.esegui(["curl", "--noproxy", "", "--silent", "--show-error", "--max-time", "60",
                              "--socks5-hostname", f"127.0.0.1:{socks}",
                              "--write-out", "\n%{http_code}", f"http://127.0.0.1:{porta_web}/"],
                             timeout=90)
    except subprocess.TimeoutExpired:
        return False, "curl non ha risposto entro 90 s"
    except OSError as e:
        return False, f"curl non eseguibile: {e}"
    corpo, _, codice = r.stdout.rpartition("\n")
    if r.returncode != 0:
        return False, f"curl uscito con {r.returncode}: {r.stderr.strip()[:120]}"
    if codice.strip() != "200":
        return False, f"HTTP {codice.strip() or '?'}"
    if corpo.encode() != atteso:
        return False, "HTTP 200 ma con un contenuto diverso da quello di questa esecuzione"
    return True, "HTTP 200, contenuto di questa esecuzione"


# --- BR-03: cattura nuova, avviata e chiusa in modo verificato ----------------------

def conta_pacchetti(container, pcap: str, filtro: str) -> int | None:
    """Pacchetti della cattura che soddisfano il filtro; None se tshark fallisce o l'output è incoerente."""
    try:
        r = container.esegui(["tshark", "-r", pcap, "-Y", filtro, "-T", "fields", "-e", "frame.number"],
                             timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    righe = [x.strip() for x in r.stdout.splitlines() if x.strip()]
    if not all(x.isdigit() for x in righe):
        return None
    return len(righe)


def cattura_obfs4(container, cartella_host: Path, porta_pt: str, genera_traffico, esiti: Esiti,
                  durata: float = DURATA_CATTURA, attesa_avvio: float = ATTESA_AVVIO,
                  esecuzione: str | None = None) -> bool:
    """Cattura il traffico sulla porta obfs4 durante una richiesta verificata e lo analizza.

    `cartella_host` è la cartella montata nel container come /lab/net.
    Restituisce True solo se tutti i controlli della cattura passano.
    """
    esecuzione = esecuzione or time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    nome = f"verifica-obfs4-{esecuzione}.pcap"
    pcap, file_host = f"/lab/net/{nome}", cartella_host / nome
    if not esiti.controlla("Cattura: file nuovo per questa esecuzione", not file_host.exists(), nome):
        return False

    inizio = time.time()
    try:
        proc = container.avvia(["timeout", "--preserve-status", "-s", "INT", str(int(durata)),
                                "tcpdump", "-i", "lo", "-U", "-w", pcap, f"tcp port {porta_pt}"],
                               utente="0")
    except OSError as e:
        esiti.controlla("Cattura: tcpdump avviato", False, f"impossibile avviarlo: {e}")
        return False

    stderr: list[str] = []
    pronto = threading.Event()

    def leggi_stderr() -> None:
        for riga in proc.stderr:
            stderr.append(riga.rstrip())
            if "listening on" in riga:
                pronto.set()

    lettore = threading.Thread(target=leggi_stderr, daemon=True)
    lettore.start()

    def ferma_tcpdump() -> None:
        try:
            container.esegui(["pkill", "-INT", "-f", nome], timeout=15, utente="0")
        except (subprocess.TimeoutExpired, OSError):
            pass
        try:
            proc.kill()
            proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass

    if not pronto.wait(attesa_avvio):
        ferma_tcpdump()
        lettore.join(timeout=5)
        esiti.controlla("Cattura: tcpdump avviato", False,
                        "nessun 'listening on' entro {:.0f} s: {}".format(attesa_avvio, " | ".join(stderr)[-160:]))
        return False
    esiti.controlla("Cattura: tcpdump avviato", True, stderr[-1][:80] if stderr else "")

    try:
        ok_traffico, dettaglio = genera_traffico()
    except Exception as e:                          # l'errore va registrato, non nascosto
        ok_traffico, dettaglio = False, f"eccezione: {e!r}"
    esiti.controlla("Cattura: richiesta di traffico attraverso il bridge verificata", ok_traffico, dettaglio)

    try:
        codice = proc.wait(timeout=durata + 30)
    except subprocess.TimeoutExpired:
        ferma_tcpdump()
        lettore.join(timeout=5)
        esiti.controlla("Cattura: tcpdump terminato correttamente", False, "non terminato in tempo: interrotto")
        return False
    lettore.join(timeout=5)
    catturati = next((int(m.group(1)) for r in stderr for m in [re.search(r"(\d+) packets? captured", r)] if m), None)
    if not esiti.controlla("Cattura: tcpdump terminato correttamente", codice == 0,
                           f"codice {codice}" + (f", {catturati} pacchetti catturati" if catturati is not None else "")):
        return False
    if not ok_traffico:
        return False

    try:
        dimensione = file_host.stat().st_size
        with file_host.open("rb") as f:
            magic = f.read(4)
        recente = file_host.stat().st_mtime >= inizio - 1
        impronta = hashlib.sha256(file_host.read_bytes()).hexdigest()
    except OSError as e:
        esiti.controlla("Cattura: file presente, leggibile e di questa esecuzione", False, str(e))
        return False
    if not esiti.controlla("Cattura: file presente, leggibile e di questa esecuzione",
                           magic in MAGIC_PCAP and recente and dimensione > INTESTAZIONE_PCAP,
                           f"{dimensione} byte, formato {'pcap' if magic in MAGIC_PCAP else 'sconosciuto'}"
                           f"{'' if recente else ', più vecchio dell’avvio'}, sha256 {impronta}"):
        return False

    totali = conta_pacchetti(container, pcap, f"tcp.port == {porta_pt}")
    con_dati = conta_pacchetti(container, pcap, f"tcp.port == {porta_pt} && tcp.len > 0")
    tls = conta_pacchetti(container, pcap, "tls")
    if not esiti.controlla("Cattura: analisi tshark riuscita", None not in (totali, con_dati, tls),
                           f"totali={totali} con dati={con_dati} TLS={tls}"):
        return False
    if not esiti.controlla("Cattura: risultati coerenti", 0 <= tls <= totali and con_dati <= totali,
                           f"TLS {tls}, con dati {con_dati}, totali {totali}"):
        return False
    if not esiti.controlla("Lab 10: la cattura sulla porta obfs4 contiene traffico con dati",
                           con_dati > 0, f"{con_dati} pacchetti con dati su {totali}"):
        return False
    return esiti.controlla("Lab 10: nessun pacchetto della cattura riconosciuto come TLS da tshark",
                           tls == 0, f"{tls} su {totali} (non prova la resistenza di obfs4 al rilevamento)")


# --- programma ----------------------------------------------------------------------

def socks_del_client(nodo: Path) -> str:
    m = re.search(r"^SocksPort (?:\S*:)?(\d+)", (nodo / "torrc").read_text(), re.M)
    if not m:
        raise ValueError(f"SocksPort assente nel torrc di {nodo.name}")
    return m.group(1)


def verifica(nodi: Path = NODI, container=None, porta_web: int = PORTA_WEB,
             durata: float = DURATA_CATTURA, attesa_avvio: float = ATTESA_AVVIO) -> Esiti:
    container = container or Container()
    esiti = Esiti()
    client, bridge = sorted(nodi.glob("*bc")), sorted(nodi.glob("*br"))
    if not esiti.controlla("Rete bridge: client e bridge presenti", bool(client) and bool(bridge),
                           f"{[p.name for p in client + bridge]}"):
        return esiti
    cliente, ponte = client[0], bridge[0]

    log = (cliente / "notice.log").read_text(errors="replace") if (cliente / "notice.log").is_file() else ""
    esiti.controlla("Lab 10: il client con bridge completa il bootstrap", "Bootstrapped 100%" in log)
    esiti.controlla("Lab 10: il client ha il descrittore del bridge", "new bridge descriptor" in log)
    socks = socks_del_client(cliente)
    m = re.search(r"^ServerTransportListenAddr obfs4 \S*:(\d+)", (ponte / "torrc").read_text(), re.M)

    # BR-01: il server vive per tutta la verifica, cattura compresa, e si chiude comunque.
    with ServerLaboratorio(porta=porta_web) as server:
        ok, dettaglio = richiesta_attraverso_bridge(container, socks, server.porta, server.corpo)
        esiti.controlla("Lab 10: richiesta web attraverso il bridge", ok, dettaglio)
        if esiti.controlla("Lab 10: il bridge annuncia una porta obfs4", bool(m)):
            cattura_obfs4(container, nodi.parent, m.group(1),
                          lambda: richiesta_attraverso_bridge(container, socks, server.porta, server.corpo),
                          esiti, durata=durata, attesa_avvio=attesa_avvio)
    return esiti


def main() -> int:
    try:
        esiti = verifica()
    except Exception as e:                          # un'eccezione è un fallimento dichiarato
        print(f"[NO!] Lab 10: verifica interrotta da un errore — {e!r}")
        return 1
    print(f"\n{sum(ok for _, ok, _ in esiti.righe)}/{len(esiti.righe)} controlli superati")
    return 0 if esiti.tutti_ok else 1


if __name__ == "__main__":
    sys.exit(main())
