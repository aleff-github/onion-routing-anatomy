# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio 11 (capitolo 18): isolamento degli stream osservato con Stem.
import re, subprocess, time
from stem import StreamStatus
from stem.control import Controller, EventType

DESTINAZIONE = "127.0.0.1:8080"
SOCKS = "127.0.0.1:9008"

assegnati, avvisi = [], []


def su_stream(ev):
    # Solo gli stream verso la nostra destinazione: tor apre di continuo stream propri
    # (le richieste di directory), che falserebbero il conteggio.
    if ev.status == StreamStatus.SUCCEEDED and ev.target == DESTINAZIONE:
        assegnati.append((ev.id, ev.circ_id, ev.target))


def tunnel(c, circ: str) -> str:
    """Il circuito può far parte di un insieme Conflux (due \"gambe\" collegate, cap. 31):
    in quel caso ciò che conta per l'isolamento è l'insieme, non la singola gamba."""
    for riga in c.get_info("circuit-status").splitlines():
        if riga.split(" ", 1)[0] == circ:
            r = re.search(r"CONFLUX_ID=(\w+)", riga)
            return f"conflux {r.group(1)[:8]}" if r else f"circuito {circ}"
    return f"circuito {circ}"


def attendi_tunnel(c, secondi=30):
    """Aspetta che tor abbia ricostruito almeno un insieme Conflux completo (due gambe)."""
    for _ in range(secondi * 2):
        insiemi = re.findall(r"^\d+ BUILT .*CONFLUX_ID=(\w+)", c.get_info("circuit-status"), re.M)
        if any(insiemi.count(x) >= 2 for x in insiemi):
            return
        time.sleep(0.5)


def richiesta(c, credenziali=None):
    """Esegue una richiesta e restituisce il circuito su cui tor l'ha instradata.
    Si prende l'ultimo evento: se un tentativo fallisce, tor riprova lo stream su un
    altro circuito ed emette un secondo SUCCEEDED."""
    assegnati.clear()
    cmd = ["curl", "--noproxy", "", "-s", "-o", "/dev/null", "--socks5-hostname", SOCKS, f"http://{DESTINAZIONE}/"]
    if credenziali:
        cmd[1:1] = ["--proxy-user", credenziali]
    subprocess.run(cmd, check=True)
    for _ in range(20):
        time.sleep(0.5)
        if assegnati:
            break
    if not assegnati:
        return "?", []
    circ = assegnati[-1][1]
    return tunnel(c, circ), [x[1] for x in c.get_circuit(circ).path]


def newnym(c, annuncia=False):
    """NEWNYM è onorato al massimo una volta ogni 10 secondi (MAX_SIGNEWNYM_RATE in
    src/core/mainloop/mainloop.c): se arriva prima, tor lo rinvia e lo scrive nel log.
    Qui aspettiamo che sia davvero applicato, altrimenti arriverebbe a metà delle prove."""
    avvisi.clear()
    c.signal("NEWNYM")
    time.sleep(2)
    for m in list(avvisi):
        r = re.search(r"Rate limiting NEWNYM request: delaying by (\d+) second", m)
        if r:
            if annuncia:
                print(f"(NEWNYM rinviato di {r.group(1)} s)")
            time.sleep(int(r.group(1)) + 1)


with Controller.from_port(port=8008) as c:
    c.authenticate()
    c.add_event_listener(su_stream, EventType.STREAM)
    c.add_event_listener(lambda ev: avvisi.append(ev.message), EventType.NOTICE)
    newnym(c)                     # si parte da circuiti nuovi, senza NEWNYM in sospeso
    attendi_tunnel(c)             # e con almeno un tunnel già pronto: altrimenti le prime
                                  # richieste finiscono su tunnel appena costruiti e diversi
    for credenziali in ["sito-a.example:x1", "sito-a.example:x1", "sito-b.example:x2", None]:
        circ, percorso = richiesta(c, credenziali)
        nome = credenziali.split(":")[0] if credenziali else "-"
        print(f"credenziali {nome:15s} -> {circ:22s} {percorso}")
    newnym(c, annuncia=True)
    circ, _ = richiesta(c, "sito-a.example:x1")
    print(f"dopo NEWNYM, sito-a.example  -> {circ}")
