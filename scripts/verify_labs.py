#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Riesegue dal vivo i laboratori del libro sulla rete privata e ne verifica i risultati.

L'ambiente canonico dell'edizione italiana è labs/it/: codice in labs/it/codice, rete e
script in labs/it/laboratorio, dati pubblici in labs/it/dati.

Uso: con la rete avviata (make -C labs/it avvia), dalla radice del repository:
    python3 scripts/verify_labs.py
    python3 scripts/verify_labs.py --controlla-ambiente   # solo il controllo iniziale
    python3 scripts/verify_labs.py --solo-offline         # solo i Laboratori 2, 7, 15, 19
Prima di qualunque prova controlla, in sola lettura, che il container torlibro-rete sia
stato avviato da labs/it/laboratorio: altrimenti gli script eseguiti nel container e i file letti
dall'host apparterrebbero a due reti diverse. Non avvia né ferma Docker.
Serve a controllare che il testo del libro resti vero quando cambia la versione di tor.
"""
import hashlib
import http.server
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
AMBIENTE = RADICE / "labs" / "it"          # ambiente canonico dell'edizione italiana
CODICE = AMBIENTE / "codice"
LAB = AMBIENTE / "laboratorio"
DATI = AMBIENTE / "dati" / "collector"
CONTAINER = "torlibro-rete"
sys.path.insert(0, str(CODICE))

from torlab.canale import ErroreCanale, apri_canale                        # noqa: E402
from torlab.celle import Cella, Comando, descrivi                           # noqa: E402
from torlab.circuito import costruisci                                     # noqa: E402
from torlab.directory import (analizza_certificati, analizza_consenso,     # noqa: E402
                              analizza_microdescrittori, scarica, verifica_consenso)
from torlab.laboratorio import relay                                       # noqa: E402
from torlab.ntor import (HTYPE_NTOR, HTYPE_NTOR_V3, codifica_estensioni,     # noqa: E402
                         corpo_create2, create_fast_client, create_fast_completa,
                         decodifica_estensioni, hdata_created2, ntor3_client_fine,
                         ntor3_client_inizio, ntor_client_fine, ntor_client_inizio)
from torlab.stream import Stream                                           # noqa: E402

esiti = []
saltati = []          # laboratori non eseguiti: non entrano nel totale, ma vanno dichiarati


def salta(nome, motivo):
    saltati.append(nome)
    print(f"[--] {nome}: {motivo}")


def controlla(nome, condizione, dettaglio=""):
    esiti.append(bool(condizione))
    print(f"[{'OK ' if condizione else 'NO!'}] {nome}" + (f" — {dettaglio}" if dettaglio else ""))


def lab1():
    for n in ("003r", "006e", "000a"):
        r = relay(n)
        c = apri_canale("127.0.0.1", r.porta, identita_attesa=r.id_ed)
        tipi = [x.split()[1] for x in c.registro[1:5]]
        controlla(f"Lab 1: canale verso {n}", c.versione == 5 and tipi == ["VERSIONS", "CERTS", "AUTH_CHALLENGE", "NETINFO"]
                  and c.metodi_auth == [3], f"v{c.versione}, {c.registro[0]}")
    try:
        apri_canale("127.0.0.1", relay("004r").porta, identita_attesa=relay("003r").id_ed)
        controlla("Lab 1: identità sbagliata rifiutata", False)
    except ErroreCanale:
        controlla("Lab 1: identità sbagliata rifiutata", True)


def lab3():
    g = relay("003r")
    c = apri_canale("127.0.0.1", g.porta, identita_attesa=g.id_ed)

    def crea(circ, htype, hdata):
        c.invia(Cella(circ, Comando.CREATE2, corpo_create2(htype, hdata)))
        return c.ricevi()

    st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([]))
    r = crea(0x80000001, HTYPE_NTOR_V3, hd)
    ntor3_client_fine(st, hdata_created2(r.corpo))
    controlla("Lab 3: ntor-v3", r.comando == Comando.CREATED2)
    st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([(1, b"")]))
    sm, _ = ntor3_client_fine(st, hdata_created2(crea(0x80000002, HTYPE_NTOR_V3, hd).corpo))
    controlla("Lab 3: ntor-v3 con CC", decodifica_estensioni(sm) == [(2, b"\x1f")], str(decodifica_estensioni(sm)))
    st, hd = ntor_client_inizio(g.id_rsa, g.ntor)
    ntor_client_fine(st, hdata_created2(crea(0x80000003, HTYPE_NTOR, hd).corpo))
    controlla("Lab 3: ntor", True)
    x, corpo = create_fast_client()
    c.invia(Cella(0x80000004, Comando.CREATE_FAST, corpo))
    create_fast_completa(x, c.ricevi().corpo)
    controlla("Lab 3: CREATE_FAST", True)
    st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([]))
    r = crea(0x80000005, HTYPE_NTOR_V3, hd[:-1] + bytes([hd[-1] ^ 1]))
    controlla("Lab 3: MAC alterato → DESTROY PROTOCOL", r.comando == Comando.DESTROY and r.corpo[0] == 1)
    st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([(3, b"\x02\x06")]))
    r = crea(0x80000006, HTYPE_NTOR_V3, hd)
    controlla("Lab 3: CGO senza CC rifiutato", r.comando == Comando.DESTROY)


def lab4_5(cartella):
    circ = costruisci([relay("003r"), relay("004r"), relay("006e")])
    controlla("Lab 4: circuito di tre salti", len(circ.cripto.salti) == 3)
    s = Stream(circ, 1)
    s.apri("127.0.0.1", 8080)
    s.invia(b"GET /grande.bin HTTP/1.0\r\n\r\n")
    corpo = s.ricevi_tutto().split(b"\r\n\r\n", 1)[1]
    atteso = hashlib.sha256((cartella / "grande.bin").read_bytes()).hexdigest()
    controlla("Lab 5: download di 1 MB", hashlib.sha256(corpo).hexdigest() == atteso,
              f"{s.reg.celle_data} celle, {circ.sendme_inviati} SENDME")
    # padding sul canale del circuito esteso
    circ.canale.sock.settimeout(12)
    visti, t = 0, time.time()
    try:
        while time.time() - t < 12:
            if circ.canale.ricevi().comando == Comando.PADDING:
                visti += 1
    except Exception:
        pass
    controlla("Lab 4: PADDING dopo l'estensione", visti >= 1, f"{visti} celle in 12 s")
    for cc, attese in ((True, 124), (False, 500)):
        circ = costruisci([relay("003r"), relay("004r"), relay("006e")], cc=cc)
        circ.conta_data_ricevuto = lambda: None
        s = Stream(circ, 1)
        s.apri("127.0.0.1", 8080)
        s.invia(b"GET /grande.bin HTTP/1.0\r\n\r\n")
        circ.canale.sock.settimeout(6)
        try:
            s.ricevi_tutto()
        except Exception:
            pass
        controlla(f"Lab 5: finestra senza SENDME (CC={cc})", s.reg.celle_data == attese, f"{s.reg.celle_data} celle")


def lab6():
    circ = costruisci([relay("000a")], cc=False)
    testo = scarica(circ, "/tor/status-vote/current/consensus-microdesc", 1).decode()
    cert = analizza_certificati(scarica(circ, "/tor/keys/all", 3).decode())
    c = analizza_consenso(testo)
    valide, richieste, _ = verifica_consenso(c, cert, 3)
    controlla("Lab 6: firme del consenso", valide == 3 and richieste == 2, f"{valide}/{richieste}")
    # Altera una sola cifra di una banda, qualunque valore abbia nel consenso vivo:
    # nella rete di prova le bande sono misurate e cambiano nel tempo, quindi non si
    # puo' assumere un valore fisso (una stringa assente renderebbe il test un no-op).
    import re as _re
    _bw = _re.search(r"Bandwidth=(\d+)", testo)
    alterato = analizza_consenso(testo.replace(_bw.group(0), f"Bandwidth={int(_bw.group(1)) + 1}", 1))
    controlla("Lab 6: consenso alterato rifiutato", verifica_consenso(alterato, cert, 3)[0] == 0)
    import base64
    dig = "-".join(base64.b64encode(r.microdesc).decode().rstrip("=") for r in c.relay)
    md = analizza_microdescrittori(scarica(circ, f"/tor/micro/d/{dig}", 5).decode())
    controlla("Lab 6: microdescrittori = righe m", all(r.microdesc in md for r in c.relay))


def lab8():
    import base64, calendar
    from torlab.laboratorio import NODI
    from torlab.onion import (analizza_descrittore, chiave_accecata, chiave_da_indirizzo,
                              indirizzo_onion, scarica_descrittore, tempo)
    indirizzo = (NODI / "009h/hidden_service/hostname").read_text().strip()
    A = chiave_da_indirizzo(indirizzo)
    controlla("Lab 8: indirizzo .onion", indirizzo_onion(A) == indirizzo)
    c = analizza_consenso(scarica(costruisci([relay("000a")], cc=False),
                                  "/tor/status-vote/current/consensus-microdesc", 1).decode())
    ts = lambda k: calendar.timegm(time.strptime(" ".join(c.intestazione[k]), "%Y-%m-%d %H:%M:%S"))
    t = tempo(ts("valid-after"), ts("fresh-until") - ts("valid-after"), rete_di_test=True)
    Ap = chiave_accecata(A, t.periodo, t.durata_minuti)
    try:
        scarica_descrittore(Ap, [relay("006e")])
        controlla("Lab 8: richiesta a un salto rifiutata", False)
    except Exception as e:
        controlla("Lab 8: richiesta a un salto rifiutata", "503" in str(e))
    d = analizza_descrittore(scarica_descrittore(Ap, [relay("003r"), relay("004r"), relay("006e")]), A, Ap)
    controlla("Lab 8: descrittore firmato e decifrato", len(d.punti_di_introduzione) >= 1,
              f"{len(d.punti_di_introduzione)} punti di introduzione")


def lab9():
    import subprocess
    from collections import Counter
    from torlab.laboratorio import NODI
    from torlab.ntor import create_fast_client
    torrc = NODI / "003r" / "torrc"
    originale = torrc.read_text()
    hup = ["docker", "exec", "torlibro-rete", "sh", "-c", "kill -HUP $(cat /lab/net/nodes/003r/pid)"]
    try:
        torrc.write_text(originale + "\nDoSCircuitCreationEnabled 1\nDoSCircuitCreationMinConnections 2\n"
                         "DoSCircuitCreationRate 1\nDoSCircuitCreationBurst 10\n"
                         "DoSCircuitCreationDefenseType 2\nDoSCircuitCreationDefenseTimePeriod 60 seconds\n")
        subprocess.run(hup, check=True)
        time.sleep(2)
        g = relay("003r")
        # Un indirizzo di origine nuovo a ogni esecuzione: un indirizzo già marcato da una prova
        # precedente resterebbe bloccato per tutto il periodo di difesa (60 s).
        import random
        origine = f"127.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(2, 250)}"
        canali = [apri_canale("127.0.0.1", g.porta, identita_attesa=g.id_ed, origine=origine) for _ in range(2)]
        esiti = []
        for i in range(30):
            x, corpo = create_fast_client()
            canali[0].invia(Cella(0x80000100 + i, Comando.CREATE_FAST, corpo))
            r = canali[0].ricevi()
            while r.comando in (Comando.PADDING, Comando.VPADDING):
                r = canali[0].ricevi()
            esiti.append(r.comando == Comando.CREATED_FAST)
        controlla("Lab 9: limite sui circuiti", esiti.count(True) == 9 and not esiti[9],
                  f"{esiti.count(True)} accettati su 30")
    finally:
        torrc.write_text(originale)
        subprocess.run(hup)


def lab11():
    import subprocess
    # Con Conflux attivo ciò che conta è il tunnel (i due circuiti collegati), non la singola gamba.
    # Su una rete piccola e molto sollecitata tor può comunque preferire un tunnel appena costruito:
    # in quel caso si riprova (vedi il capitolo 18).
    for _ in range(3):
        uscita = subprocess.run(["docker", "exec", "-w", "/tmp", "torlibro-rete", "python3", "/lab/isolamento.py"],
                                capture_output=True, text=True, timeout=180).stdout.splitlines()
        circ = [r.split("->")[1].split()[1] for r in uscita if "->" in r]
        if len(circ) == 5 and circ[0] == circ[1]:
            break
    controlla("Lab 11: stesse credenziali, stesso tunnel", len(circ) == 5 and circ[0] == circ[1], str(circ))
    controlla("Lab 11: credenziali diverse, tunnel diversi", len(set(circ[1:4])) == 3)
    controlla("Lab 11: NEWNYM cambia tunnel", circ[4] != circ[0])


def lab12():
    import os, subprocess
    from torlab.celle import Comando as C, ErroreCella
    from torlab.traffico import celle_da_follow
    from torlab.laboratorio import NODI
    chiavi = NODI.parent / "chiavi-verifica.log"
    chiavi.unlink(missing_ok=True)
    subprocess.run(["docker", "exec", "-u", "0", "-d", "torlibro-rete", "sh", "-c",
                    "timeout 12 tcpdump -i lo -w /lab/net/verifica.pcap 'tcp port 5104' >/dev/null 2>&1"])
    time.sleep(2)
    os.environ["SSLKEYLOGFILE"] = str(chiavi)
    try:
        costruisci([relay("004r")], cc=False)
    finally:
        del os.environ["SSLKEYLOGFILE"]
    time.sleep(11)
    trovata = []
    for i in range(8):
        out = subprocess.run(["docker", "exec", "torlibro-rete", "tshark", "-r", "/lab/net/verifica.pcap", "-o",
                              "tls.keylog_file:/lab/net/chiavi-verifica.log", "-q", "-z", f"follow,tls,raw,{i}"],
                             capture_output=True, text=True).stdout
        try:
            seq = [C(c.comando).name for _, c, _ in celle_da_follow(out)]
        except (ErroreCella, ValueError):
            # Gli altri stream TCP non sono la sessione aperta dal nostro client.
            continue
        if seq:
            trovata = seq
            break
    controlla("Lab 12: celle nel TLS decifrato", trovata[:2] == ["VERSIONS", "VERSIONS"] and "CREATED2" in trovata,
              " ".join(trovata))


def lab16():
    import subprocess
    uscita = subprocess.run(["docker", "exec", "-w", "/tmp", "torlibro-rete", "python3", "/lab/correlazione.py", "3"],
                            capture_output=True, text=True, timeout=180).stdout.splitlines()
    ultima = uscita[-1] if uscita else ""
    controlla("Lab 16: correlazione, almeno 5 abbinamenti su 6", ultima.split(":")[-1].strip() in ("5/6", "6/6"), ultima)


def lab17():
    import subprocess
    uscita = subprocess.run([sys.executable, str(LAB / "relay_early.py"), "8", "9"], capture_output=True,
                            text=True, timeout=120, env={**os.environ, "PYTHONPATH": str(CODICE)}).stdout
    righe = uscita.splitlines()
    controlla("Lab 17: 8 celle RELAY_EARLY accettate", len(righe) == 2 and righe[0].endswith("CONNECTED"), uscita)
    controlla("Lab 17: la nona chiude il circuito", len(righe) == 2 and "distrutto, motivo 1" in righe[1])


def lab18():
    import subprocess
    r = subprocess.run(["docker", "exec", "-w", "/tmp", "torlibro-rete", "python3", "/lab/fuga_dns.py"],
                       capture_output=True, text=True, timeout=180)
    righe = r.stdout.splitlines()
    controlla("Lab 18: tor segnala la richiesta con solo IP", len(righe) == 3 and "only an IP" in righe[0], str(righe))
    # Gli exit hanno come unico nameserver il resolver della rete privata (dns_locale.py):
    # un 200 con --socks5-hostname è una risoluzione fatta dall'exit. Se la stessa prova è
    # stata ripetuta da poco, l'exit risponde dalla sua cache (TTL minimo di tor: 5 min).
    risolto = "dns locale: localhost A 127.0.0.1" in r.stderr
    controlla("Lab 18: nome risolto all'exit",
              len(righe) == 3 and "HTTP 200" in righe[1] and "DNS resolution" in righe[1],
              "resolver locale interrogato" if risolto else "nessuna domanda al resolver: risposta dalla cache dell'exit")
    controlla("Lab 18: SafeSocks rifiuta", len(righe) == 3 and righe[2].endswith("HTTP 000"))


def lab20():
    import subprocess
    # Percorso del cap. 30 (labs/it/vendor/arti); fonti/arti è il percorso storico.
    candidati = [AMBIENTE / "vendor" / "arti" / "target" / "release" / "arti",
                 RADICE / "fonti" / "arti" / "target" / "release" / "arti"]
    arti = next((p for p in candidati if p.exists()), None)
    if arti is None:
        salta("Lab 20", "arti non compilato, saltato (vedi il cap. 30, passo 1)")
        return
    subprocess.run([sys.executable, str(LAB / "arti_config.py")], check=True, capture_output=True)
    registro = LAB / "net" / "arti" / "arti.log"
    # Arti si rifiuta di girare come root; in un container in cui si è root lo si consente
    # esplicitamente, senza toccare arti.toml (identico a quello del cap. 30).
    come_root = ["-o", "application.allow_running_as_root=true"] if os.geteuid() == 0 else []
    proc = subprocess.Popen([str(arti), "proxy", "-p", "9150", "-c", str(LAB / "net" / "arti" / "arti.toml"),
                             *come_root],
                            stdout=registro.open("w"), stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            if "proxy now functional" in registro.read_text():
                break
            time.sleep(1)
        controlla("Lab 20: Arti completa il bootstrap nella rete privata", "proxy now functional" in registro.read_text())
        # --noproxy "": come nel cap. 30, NO_PROXY non deve far aggirare il proxy SOCKS di Arti.
        codice = subprocess.run(["curl", "--noproxy", "", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "30",
                                 "--socks5-hostname", "127.0.0.1:9150", "http://127.0.0.1:8080/"],
                                capture_output=True, text=True).stdout
        controlla("Lab 20: scaricamento attraverso Arti", codice == "200", codice)
    finally:
        proc.terminate()
        proc.wait()


def lab13():
    import subprocess
    uscita = subprocess.run([sys.executable, str(LAB / "scoperta_ristretta.py")],
                            capture_output=True, text=True, timeout=300,
                            env={**os.environ, "PYTHONPATH": str(CODICE)}).stdout.splitlines()
    controlla("Lab 13: senza chiave il descrittore non si decifra",
              len(uscita) == 3 and uscita[1].endswith("000"), str(uscita))
    controlla("Lab 13: con la chiave il servizio risponde",
              len(uscita) == 3 and uscita[2].endswith("200"))


def lab14():
    import subprocess
    uscita = subprocess.run([sys.executable, str(LAB / "politica_uscita.py")],
                            capture_output=True, text=True, timeout=300,
                            env={**os.environ, "PYTHONPATH": str(CODICE)}).stdout.splitlines()
    atteso = ["EXITPOLICY indirizzo=127.0.0.1 TTL=1800", "CONNECTED", "MISC"]
    for riga, fine in zip(uscita, atteso):
        controlla(f"Lab 14: {riga.split(' -> ')[0]}", riga.endswith(fine), riga)
    controlla("Lab 14: tre prove eseguite", len(uscita) == 3, str(uscita))


# --- laboratori che non richiedono la rete: si verificano sui dati salvati ---------

def _dato(nome):
    """Il file in labs/it/dati/collector (make -C labs/it data) o, in subordine, nel percorso storico."""
    for cartella in (DATI, RADICE / "fonti" / "collector"):
        if (cartella / nome).exists():
            return cartella / nome
    return DATI / nome


CONSENSO = _dato("consensus-microdesc-2026-09-23-15")
CERTIFICATI = _dato("certs")


def lab2():
    """Lab 2 (cap. 8): codifica e decodifica delle celle."""
    from torlab.celle import (Cella, Comando, ComandoRelay, MessaggioRelay, codifica, codifica_relay,
                              decodifica, decodifica_relay)
    c = Cella(0x80000001, Comando.RELAY, b"\x01" * 509)
    grezza = codifica(c, 4)
    controlla("Lab 2: cella fissa lunga 514 byte", len(grezza) == 514, str(len(grezza)))
    letta, resto = decodifica(grezza, 4)
    controlla("Lab 2: cella invariata dopo codifica e decodifica",
              (letta.circ_id, letta.comando, letta.corpo) == (c.circ_id, c.comando, c.corpo) and resto == b"")
    m = MessaggioRelay(ComandoRelay.BEGIN, 1, b"127.0.0.1:80\x00")
    rit = decodifica_relay(codifica_relay(m))
    controlla("Lab 2: messaggio relay invariato dopo codifica e decodifica",
              (rit.comando, rit.stream_id, rit.dati) == (m.comando, m.stream_id, m.dati))


def lab7():
    """Lab 7 (cap. 13): selezione pesata dei percorsi sul consenso pubblico."""
    import random
    from torlab.directory import analizza_consenso
    from torlab.percorso import Selettore, rete16
    if not CONSENSO.exists():
        salta("Lab 7", "consenso di CollecTor assente, saltato (make -C labs/it data)")
        return
    c = analizza_consenso(CONSENSO.read_text())
    sel, rng = Selettore(c), random.Random(7)
    percorsi = [sel.percorso(rng) for _ in range(500)]
    # I nickname non sono unici nella rete pubblica (151 sono usati da più relay):
    # i relay si distinguono per identità.
    controlla("Lab 7: tre relay distinti in ogni percorso",
              all(len({r.id_rsa for r in p}) == 3 for p in percorsi))
    controlla("Lab 7: reti /16 distinte in ogni percorso",
              all(len({rete16(r) for r in p}) == 3 for p in percorsi))
    controlla("Lab 7: il primo salto è sempre un guard",
              all("Guard" in p[0].flag for p in percorsi))
    controlla("Lab 7: l'ultimo salto è sempre un exit",
              all("Exit" in p[2].flag and "BadExit" not in p[2].flag for p in percorsi))


def lab15():
    """Lab 15 (cap. 24): statistiche dal consenso, come stampate nel libro."""
    from torlab.directory import analizza_consenso, analizza_certificati, verifica_consenso
    from torlab.metriche import riassunto, stima_utenti
    if not CONSENSO.exists():
        salta("Lab 15", "consenso di CollecTor assente, saltato (make -C labs/it data)")
        return
    c = analizza_consenso(CONSENSO.read_text())
    r = riassunto(c)
    controlla("Lab 15: numero di relay del capitolo 24", r["relay"] == 9358, str(r["relay"]))
    controlla("Lab 15: quote di banda di guard ed exit",
              round(r["quota_banda_guard"], 3) == 0.701 and round(r["quota_banda_exit"], 3) == 0.331)
    controlla("Lab 15: stima degli utenti", stima_utenti(20_000_000, 0.6) == 3_333_333)
    if CERTIFICATI.exists():
        cert = analizza_certificati(CERTIFICATI.read_text())
        valide, richieste, _ = verifica_consenso(c, cert, 9)
        controlla("Lab 6 (passo 6): firme del consenso pubblico", valide == 9 and richieste == 5,
                  f"{valide}/9")


def lab19():
    """Lab 19 (cap. 29): simulazione del tempo alla prima compromissione."""
    from torlab.directory import analizza_consenso
    from torlab.simulazione import simula
    if not CONSENSO.exists():
        salta("Lab 19", "consenso di CollecTor assente, saltato (make -C labs/it data)")
        return
    c = analizza_consenso(CONSENSO.read_text())
    fisso = simula(c, 0.05, 0.05, guard_persistente=True)
    variabile = simula(c, 0.05, 0.05, guard_persistente=False)
    controlla("Lab 19: con guard persistenti i compromessi a 180 giorni sono il 18,2%",
              round(100 * fisso.frazione_entro(180), 1) == 18.2,
              f"{100 * fisso.frazione_entro(180):.1f}%")
    controlla("Lab 19: senza guard persistenti sono il 100% e la mediana è 14 giorni",
              variabile.frazione_entro(180) == 1.0 and variabile.mediana() == 14)


def controlla_ambiente():
    """Interrompe tutto se la rete in uso non è quella di labs/it/laboratorio (solo letture, nessun avvio)."""
    import subprocess
    from torlab.laboratorio import NODI
    if NODI.resolve() != (LAB / "net" / "nodes").resolve():
        sys.exit(f"torlab importato da un albero inatteso: NODI={NODI}")
    if not NODI.is_dir():
        sys.exit(f"rete del laboratorio non trovata in {NODI}: avviala con make -C labs/it avvia.")
    r = subprocess.run(["docker", "inspect", "-f",
                        "{{range .Mounts}}{{if eq .Destination \"/lab\"}}{{.Source}}{{end}}{{end}}", CONTAINER],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"container {CONTAINER} non trovato: avvia la rete con make -C labs/it avvia "
                 f"({r.stderr.strip() or 'docker inspect non riuscito'})")
    montato = Path(r.stdout.strip())
    if not r.stdout.strip() or montato.resolve() != LAB.resolve():
        sys.exit(f"il container {CONTAINER} monta {montato or '(niente)'} su /lab, non {LAB}: "
                 "gli script eseguiti nel container userebbero un'altra rete. "
                 "Ferma quella rete e riavviala con make -C labs/it avvia.")
    print(f"[OK ] Ambiente: {CONTAINER} monta {LAB} su /lab; nodi in {NODI}")


def main():
    if "--controlla-ambiente" in sys.argv[1:]:
        controlla_ambiente()
        return
    if "--solo-offline" in sys.argv[1:]:
        # Laboratori 2, 7, 15 e 19: nessuna rete, nessun container.
        for passo in (lab2, lab7, lab15, lab19):
            try:
                passo()
            except Exception as e:
                controlla(f"{passo.__name__}: eccezione", False, repr(e))
        print(f"\n{sum(esiti)}/{len(esiti)} controlli superati (solo laboratori senza rete)"
              + (f"; saltati: {', '.join(saltati)}" if saltati else ""))
        sys.exit(0 if all(esiti) else 1)
    controlla_ambiente()
    with tempfile.TemporaryDirectory() as d:
        cartella = Path(d)
        (cartella / "grande.bin").write_bytes(os.urandom(1 << 20))
        class Gestore(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=d, **k)

            def log_message(self, *a):
                pass

        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), Gestore)
        except OSError as e:
            sys.exit(f"impossibile occupare la porta 8080, che serve ai Laboratori 5, 11, 16 e 20 "
                     f"come server di prova: {e}.\nChiudi il programma che la occupa "
                     f"(ss -ltnp | grep :8080) e riprova.")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        for passo in (lab1, lab2, lab3, lambda: lab4_5(cartella), lab6, lab7, lab8, lab9, lab11, lab12,
                      lab13, lab14, lab15, lab16, lab17, lab18, lab19, lab20):
            try:
                passo()
            except Exception as e:                       # un laboratorio rotto non ferma gli altri
                controlla(f"{getattr(passo, '__name__', 'lab')}: eccezione", False, repr(e))
        server.shutdown()
    print(f"\n{sum(esiti)}/{len(esiti)} controlli superati"
          + (f"; saltati (non verificati): {', '.join(saltati)}" if saltati else ""))
    sys.exit(0 if all(esiti) else 1)


if __name__ == "__main__":
    main()
