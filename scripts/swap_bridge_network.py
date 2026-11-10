#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Scambio sicuro fra la rete `libro` e la rete `libro-bridge` (make verifica-lab-bridge).

Sequenza: controlli preliminari -> arresto della rete libro -> net/ rinominata in
net-libro/ -> creazione e bootstrap di libro-bridge -> scripts/verify_bridge_lab.py ->
arresto -> rete bridge in quarantena -> net-libro/ rinominata in net/ -> confronto delle
impronte -> riavvio e bootstrap della rete libro -> rimozione della quarantena.

Garanzie:
- la rete `libro` non viene mai cancellata né copiata: solo rinominata, avanti e indietro;
- si cancella soltanto una rete bridge di provenienza dimostrata (marcatore scritto da
  questa esecuzione o, se la creazione si è fermata prima, net/ nata dopo lo spostamento
  e priva di impronte della rete libro), e solo dopo un ripristino riuscito e verificato;
- il giornale labs/it/laboratorio/verifica-bridge.stato registra fase e impronte: dopo
  un'interruzione brutale (SIGKILL, spegnimento) né questo script né `make -C labs/it
  avvia` ripartono, e la procedura manuale è in docs/it/procedura-laboratori-dal-vivo.md, §8;
- durante il ripristino SIGINT e SIGTERM vengono ignorati; i comandi figli girano in una
  sessione separata e non ricevono il Ctrl-C del terminale.

Codici di uscita:
  0  controlli del bridge superati; rete libro ripristinata e verificata
  1  controlli del bridge falliti o verifica interrotta; rete libro ripristinata e verificata
  2  non eseguito: un controllo preliminare non è passato, nessun dato modificato
  3  ripristino non riuscito o non verificabile: intervento manuale
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from loopback_network import ascolti_ss, problemi_ascolti_processi

RADICE = Path(__file__).resolve().parent.parent
LAB = RADICE / "labs" / "it" / "laboratorio"
CONTAINER = "torlibro-rete"
RETE_BRIDGE = "/lab/chutney/networks/libro-bridge"

OK, CONTROLLI_FALLITI, NON_ESEGUITO, RIPRISTINO_FALLITO = 0, 1, 2, 3
DESCRIZIONE = {OK: "controlli superati, rete libro ripristinata e verificata",
               CONTROLLI_FALLITI: "controlli del bridge falliti, rete libro ripristinata e verificata",
               NON_ESEGUITO: "non eseguito, nessun dato modificato",
               RIPRISTINO_FALLITO: "RIPRISTINO NON RIUSCITO: docs/it/procedura-laboratori-dal-vivo.md, §8"}


class Interruzione(Exception):
    """SIGTERM ricevuto durante la verifica: si annulla, ma il ripristino va fatto."""


class ErroreScambio(Exception):
    pass


class Comandi:
    """Comandi verso il container e sull'host (sostituiti nei test)."""

    def __init__(self, container: str = CONTAINER):
        self.container = container

    def docker(self, *args: str, timeout: float = 120, env: dict[str, str] | None = None):
        base = ["docker", "exec"] + [x for k, v in (env or {}).items() for x in ("-e", f"{k}={v}")]
        return subprocess.run(base + [self.container, *args], capture_output=True, text=True,
                              timeout=timeout, start_new_session=True)

    def host(self, *args: str, timeout: float = 900):
        # L'output resta sul terminale: è il resoconto dei controlli.
        return subprocess.run(list(args), cwd=RADICE, timeout=timeout, start_new_session=True)


def istantanea(net: Path) -> dict[str, str]:
    """sha256 di torrc, chiavi e identità di ogni nodo: ciò che il ripristino deve ritrovare."""
    nodi = net / "nodes"
    if not nodi.is_dir():
        return {}
    file = [p for p in nodi.glob("*/*") if p.is_file() and (p.name == "torrc" or p.name.startswith("fingerprint"))]
    file += [p for p in nodi.glob("*/keys/*") if p.is_file()]
    file += [p for p in nodi.glob("*/*/hs_ed25519_*") if p.is_file()]
    return {str(p.relative_to(nodi)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(file)}


def impronte(net: Path) -> dict[str, str]:
    """Impronte dei nodi (nome -> contenuto del file fingerprint); OSError se illeggibili."""
    nodi = net / "nodes"
    if not nodi.is_dir():
        return {}
    return {p.parent.name: p.read_text().strip() for p in sorted(nodi.glob("*/fingerprint"))}


class Scambio:
    def __init__(self, lab: Path = LAB, comandi: Comandi | None = None,
                 attesa_arresto: float = 15, proteggi_ripristino: bool = False,
                 attesa_salute: float = 720, intervallo_salute: float = 30, successi_salute: int = 3):
        self.lab = lab
        self.net, self.net_libro = lab / "net", lab / "net-libro"
        self.giornale, self.file_esito = lab / "verifica-bridge.stato", lab / "esito-bridge"
        self.catture = lab / "catture"         # PCAP del Lab 10: privati, esclusi da git
        self.cmd = comandi or Comandi()
        self.attesa_arresto = attesa_arresto
        # Dopo una pausa l'onion service torna raggiungibile solo quando cambia il periodo
        # dei descrittori (circa 8 minuti nella rete di prova): chutney verify si ripete
        # fino a 12 minuti prima di dichiarare la rete non sana.
        # Un solo successo non basta: nella prima esecuzione reale (28/10/2026) chutney
        # verify è riuscito subito dopo il riavvio e poi è fallito per 4 minuti (onion
        # service). Servono successi_salute riuscite consecutive, a intervallo_salute.
        self.attesa_salute, self.intervallo_salute = attesa_salute, intervallo_salute
        self.successi_salute = successi_salute
        self.stato_libro: dict[str, str] = {}
        self.nodi_libro = 0
        self.proteggi_ripristino = proteggi_ripristino
        self.esecuzione = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        self.quarantena = lab / f"net-bridge-{self.esecuzione}"
        self.marcatore = f".creata-da-verifica-bridge-{self.esecuzione}"
        self.impronte_libro: dict[str, str] = {}
        self.fase = "nessuna"           # ultima fase scritta nel giornale
        self.spostata = False           # la rete libro è stata (forse) rinominata

    # --- utilità ---------------------------------------------------------------------

    def log(self, msg: str) -> None:
        print(f"[scambio] {msg}", flush=True)

    def scrivi_giornale(self, fase: str) -> None:
        self.fase = fase
        dati = {"fase": fase, "esecuzione": self.esecuzione, "impronte_libro": self.impronte_libro,
                "net_libro": str(self.net_libro), "quarantena": str(self.quarantena)}
        tmp = self.giornale.with_name(self.giornale.name + ".tmp")
        tmp.write_text(json.dumps(dati, indent=1, ensure_ascii=False) + "\n")
        os.replace(tmp, self.giornale)          # scrittura atomica

    def docker(self, *args: str, timeout: float = 120, env=None) -> tuple[int, str]:
        try:
            r = self.cmd.docker(*args, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            self.log(f"timeout: docker exec … {' '.join(args)}")
            return 124, ""
        except OSError as e:
            self.log(f"impossibile eseguire docker: {e}")
            return 127, ""
        if r.returncode != 0:
            self.log(f"docker exec … {' '.join(args)} -> {r.returncode}: {(r.stderr or '').strip()[:300]}")
        return r.returncode, r.stdout or ""

    def conta_processi(self) -> dict[str, int] | None:
        """Processi vivi di tor e obfs4proxy nel container; None se non si può sapere.

        Gli zombie (stato Z) non contano: sono già terminati e non hanno né porte né file
        aperti; in un container senza --init restano finché il processo 1 non li raccoglie,
        e pgrep li troverebbe ancora. Un errore di docker o di ps dà None, che non va mai
        scambiato per una rete ferma."""
        codice, out = self.docker("sh", "-c", 'ps -eo stat=,comm=; echo "ps=$?"', timeout=15)
        righe = out.strip().splitlines()
        if codice != 0 or not righe or righe[-1] != "ps=0":
            return None
        conti = {"tor": 0, "obfs4proxy": 0}
        for riga in righe[:-1]:
            campi = riga.split()
            if len(campi) == 2 and campi[1] in conti and not campi[0].startswith("Z"):
                conti[campi[1]] += 1
        return conti

    def processi_attivi(self) -> dict[str, bool] | None:
        conti = self.conta_processi()
        return None if conti is None else {nome: n > 0 for nome, n in conti.items()}

    def tor_attivo(self) -> bool:
        processi = self.processi_attivi()
        return processi is None or any(processi.values())

    def ferma_tor(self) -> bool:
        """Ferma tor e obfs4proxy nel container; True solo se l'arresto è confermato."""
        self.docker("chutney", "stop", timeout=120)
        self.docker("sh", "-c", "pkill -x tor; pkill -x obfs4proxy; true", timeout=15)
        scadenza = time.monotonic() + self.attesa_arresto
        while True:
            if not self.tor_attivo():
                return True
            if time.monotonic() >= scadenza:
                break
            time.sleep(1)
        self.log(f"processi ancora attivi o stato ignoto ({self.processi_attivi()}): invio SIGKILL")
        self.docker("sh", "-c", "pkill -9 -x tor; pkill -9 -x obfs4proxy; true", timeout=15)
        time.sleep(min(2, self.attesa_arresto))
        return not self.tor_attivo()

    def avvia_libro(self) -> bool:
        """Riavvio della rete libro (come make riavvia), con attesa del bootstrap."""
        for pid in (self.net / "nodes").glob("*/pid"):
            pid.unlink()
        return (self.docker("chutney", "start", timeout=300)[0] == 0
                and self.docker("chutney", "start", timeout=300, env={"CHUTNEY_LAUNCH_PHASE": "2"})[0] == 0
                and self.docker("chutney", "wait_for_bootstrap", timeout=600)[0] == 0)

    def ascolti(self) -> list[tuple[str, int, str]] | None:
        codice, out = self.docker("ss", "-ltnpH", timeout=15)
        return ascolti_ss(out) if codice == 0 else None

    def controlla_isolamento_bridge(self) -> None:
        """BR-06: prima del traffico, nessun ascolto di tor o obfs4proxy fuori dal loopback
        e obfs4proxy in ascolto sull'indirizzo del torrc del bridge."""
        elenco = self.ascolti()
        if elenco is None:
            raise ErroreScambio("ascolti della rete bridge non leggibili: prova interrotta")
        self.log("ascolti della rete bridge: " + ", ".join(
            f"{p}@{i}:{n}" for i, n, p in sorted(elenco, key=lambda x: x[1]) if p in ("tor", "obfs4proxy")))
        problemi = problemi_ascolti_processi(elenco)
        if problemi:
            raise ErroreScambio("ascolti non confinati al loopback: " + "; ".join(problemi))
        pt = None
        for t in (self.net / "nodes").glob("*/torrc"):
            m = re.search(r"^ServerTransportListenAddr obfs4 (\S+):(\d+)$", t.read_text(), re.M)
            if m:
                pt = (m.group(1), int(m.group(2)))
        if pt is None or pt[0] != "127.0.0.1":
            raise ErroreScambio(f"ServerTransportListenAddr obfs4 non su 127.0.0.1: {pt}")
        if (pt[0], pt[1], "obfs4proxy") not in elenco:
            raise ErroreScambio(f"obfs4proxy non in ascolto su {pt[0]}:{pt[1]}")
        self.log(f"isolamento verificato: tutto su loopback, obfs4proxy su {pt[0]}:{pt[1]}")

    def salute_libro(self) -> bool:
        """Dopo il bootstrap: processi, traffico reale (exit e onion service), ascolti, impronte."""
        conti = self.conta_processi()
        if conti is None or conti["tor"] != self.nodi_libro:
            self.log(f"processi tor vivi: {conti and conti['tor']} invece di {self.nodi_libro}")
            return False
        processi = self.processi_attivi()
        if processi is None or processi["obfs4proxy"]:
            self.log(f"obfs4proxy ancora attivo o stato ignoto: {processi}")
            return False
        scadenza = time.monotonic() + self.attesa_salute
        di_fila = 0
        while True:
            codice, out = self.docker("sh", "-c", "chutney verify 2>&1", timeout=300)
            if codice == 0 and "Transmission: Success" in out:
                di_fila += 1
                if di_fila >= self.successi_salute:
                    break
            else:
                if di_fila:
                    self.log(f"chutney verify fallito dopo {di_fila} successi: si ricomincia a contare")
                di_fila = 0
            if time.monotonic() >= scadenza:
                self.log(f"chutney verify senza {self.successi_salute} successi consecutivi entro "
                         f"{self.attesa_salute:.0f} s: rete non sana")
                return False
            if not di_fila:
                self.log("chutney verify non ancora riuscito (dopo una pausa l'onion service torna "
                         f"raggiungibile al cambio di periodo): nuovo tentativo tra {self.intervallo_salute:.0f} s")
            time.sleep(self.intervallo_salute)
        self.log(f"chutney verify riuscito {self.successi_salute} volte di fila: traffico attraverso "
                 "gli exit e verso l'onion service")
        elenco = self.ascolti()
        problemi = ["ascolti non leggibili"] if elenco is None else problemi_ascolti_processi(elenco)
        if problemi:
            self.log("ascolti della rete libro non confinati: " + "; ".join(problemi))
            return False
        if impronte(self.net) != self.impronte_libro:
            self.log("impronte cambiate dopo il riavvio")
            return False
        return True

    def collega_nodi(self) -> None:
        """Chutney crea net/nodes.<istante> e un net/nodes valido solo nel container."""
        candidati = sorted(p.name for p in self.net.glob("nodes.*") if p.is_dir())
        if not candidati:
            raise ErroreScambio("chutney init non ha creato net/nodes.*")
        link = self.net / "nodes"
        if link.is_symlink():
            link.unlink()
        elif link.exists():
            raise ErroreScambio("net/nodes esiste e non è un collegamento: non lo tocco")
        link.symlink_to(candidati[-1])

    def provenienza_bridge_verificata(self) -> bool:
        """True solo se net/ è certamente la rete bridge creata da questa esecuzione."""
        if not self.net.is_dir() or self.net.is_symlink():
            return False
        if (self.net / self.marcatore).is_file():
            return True
        # Creazione interrotta prima del marcatore: net/ è nata dopo lo spostamento della
        # rete libro (fase registrata) e non deve contenere nessuna delle sue impronte.
        if self.fase not in ("libro-spostata", "bridge-in-creazione") or not self.net_libro.is_dir():
            return False
        try:
            trovate = {p.read_text().strip() for p in self.net.rglob("fingerprint") if p.is_file()}
        except OSError:
            return False
        return not (trovate & set(self.impronte_libro.values()))

    # --- sequenza --------------------------------------------------------------------

    def preliminari(self) -> bool:
        """Solo letture (più la creazione del giornale): False = non si tocca niente."""
        if self.giornale.exists():
            self.log(f"{self.giornale} esiste: un'esecuzione precedente si è interrotta. "
                     "Ripristino manuale: docs/it/procedura-laboratori-dal-vivo.md, §8.")
            return False
        if self.net_libro.exists():
            self.log(f"{self.net_libro} esiste già (esecuzione interrotta?): ripristinala prima.")
            return False
        if not (self.net / "nodes").is_dir():
            self.log(f"rete libro assente in {self.net}: avviala con make -C labs/it avvia.")
            return False
        try:
            self.impronte_libro = impronte(self.net)
        except OSError as e:
            self.log(f"impronte della rete libro illeggibili: {e}")
            return False
        if not self.impronte_libro:
            self.log("nessuna impronta nei nodi della rete libro: rete incompleta, non procedo.")
            return False
        try:
            self.stato_libro = istantanea(self.net)
        except OSError as e:
            self.log(f"chiavi o torrc della rete libro illeggibili: {e}")
            return False
        self.nodi_libro = len(list((self.net / "nodes").glob("*/torrc")))
        try:
            r = self.cmd.host(sys.executable, "scripts/verify_labs.py", "--controlla-ambiente",
                              timeout=120)
        except (OSError, subprocess.TimeoutExpired) as e:
            self.log(f"controllo dell'ambiente non eseguibile: {e}")
            return False
        if r.returncode != 0:
            self.log("controllo dell'ambiente non superato: non procedo.")
            return False
        try:
            self.scrivi_giornale("arresto-libro")
        except OSError as e:
            self.log(f"impossibile scrivere {self.giornale}: {e}")
            return False
        return True

    def esegui(self) -> int:
        if not self.preliminari():
            return NON_ESEGUITO
        self.log(f"esecuzione {self.esecuzione}: registrate le impronte di "
                 f"{len(self.impronte_libro)} nodi della rete libro")
        controlli = CONTROLLI_FALLITI
        try:
            controlli = self.prova_bridge()
        except (KeyboardInterrupt, Interruzione):
            self.log("interruzione ricevuta: verifica annullata, si ripristina la rete libro")
        except Exception as e:                      # registrato, poi si ripristina
            self.log(f"errore durante la verifica: {e!r}")
        if not self.ripristina_protetto():
            return RIPRISTINO_FALLITO
        if not self.spostata:
            return NON_ESEGUITO                     # la rete libro non è mai stata rinominata
        return controlli

    def prova_bridge(self) -> int:
        self.file_esito.unlink(missing_ok=True)     # niente esiti di esecuzioni precedenti
        if not self.ferma_tor():
            raise ErroreScambio("impossibile fermare la rete libro: nessuno spostamento eseguito")
        if self.net_libro.exists():                 # rename sostituirebbe una cartella vuota
            raise ErroreScambio(f"{self.net_libro} è comparsa durante l'arresto")
        self.spostata = True
        os.rename(self.net, self.net_libro)
        self.scrivi_giornale("libro-spostata")
        self.scrivi_giornale("bridge-in-creazione")
        if self.docker("chutney", "init", "--net-from-script-path", RETE_BRIDGE, timeout=300)[0] != 0:
            raise ErroreScambio("chutney init della rete libro-bridge fallito")
        if not self.net.is_dir():
            raise ErroreScambio("chutney init non ha creato net/")
        (self.net / self.marcatore).write_text(self.esecuzione + "\n")
        self.scrivi_giornale("bridge-creata")
        if self.docker("chutney", "bootstrap", timeout=900)[0] != 0:
            self.log("bootstrap di libro-bridge non completato: lo rileveranno i controlli")
        self.collega_nodi()
        self.controlla_isolamento_bridge()
        self.scrivi_giornale("verifica-bridge")
        try:
            codice = self.cmd.host(sys.executable, "scripts/verify_bridge_lab.py", timeout=900).returncode
        except subprocess.TimeoutExpired:
            self.log("verify_bridge_lab.py non è terminato entro 900 s")
            codice = CONTROLLI_FALLITI
        self.file_esito.write_text(f"{codice}\n")
        self.log(f"codice di uscita di verify_bridge_lab.py: {codice}")
        return OK if codice == 0 else CONTROLLI_FALLITI

    def ripristina_protetto(self) -> bool:
        vecchi = {}
        if self.proteggi_ripristino:
            for s in (signal.SIGINT, signal.SIGTERM):
                vecchi[s] = signal.signal(s, signal.SIG_IGN)
        try:
            return self.ripristina()
        except Exception as e:
            self.log(f"errore durante il ripristino: {e!r}")
            return False
        finally:
            for s, h in vecchi.items():
                signal.signal(s, h)

    def ripristina(self) -> bool:
        """Rimette la rete libro in net/ e la riavvia; False se qualcosa non è verificato."""
        self.log("ripristino della rete libro")
        if not self.ferma_tor():
            # BR-05: con processi forse ancora attivi non si sposta nulla.
            self.log("arresto di tor/obfs4proxy non confermato: nessuno spostamento, "
                     "intervento manuale (docs/it/procedura-laboratori-dal-vivo.md, §8)")
            return False
        if self.net_libro.exists():
            if self.net.exists() or self.net.is_symlink():
                if not self.provenienza_bridge_verificata():
                    self.log(f"{self.net} esiste ma non è dimostrato che sia la rete bridge di "
                             "questa esecuzione: non la tocco")
                    return False
                if self.quarantena.exists():
                    self.log(f"{self.quarantena} esiste già: non sovrascrivo")
                    return False
                os.rename(self.net, self.quarantena)
                self.scrivi_giornale("bridge-in-quarantena")
            os.rename(self.net_libro, self.net)
            self.scrivi_giornale("libro-ripristinata")
        elif self.spostata and self.fase != "arresto-libro":
            self.log(f"{self.net_libro} non esiste più: non so dove sia la rete libro")
            return False
        if impronte(self.net) != self.impronte_libro:
            self.log(f"le impronte in {self.net} non coincidono con quelle registrate")
            return False
        try:
            attuale = istantanea(self.net)
        except OSError as e:
            self.log(f"chiavi o torrc illeggibili dopo il ripristino: {e}")
            return False
        if attuale != self.stato_libro:
            diversi = sorted(k for k in set(attuale) | set(self.stato_libro)
                             if attuale.get(k) != self.stato_libro.get(k))
            self.log(f"chiavi o torrc diversi da quelli registrati: {', '.join(diversi)[:300]}")
            return False
        self.log(f"impronte, chiavi e torrc coincidenti ({len(self.impronte_libro)} nodi, "
                 f"{len(self.stato_libro)} file)")
        if not self.avvia_libro():
            self.log("cartelle al loro posto, ma la rete libro non completa il bootstrap: "
                     "make riavvia, poi make -C labs/it/laboratorio verifica")
            return False
        if not self.salute_libro():
            self.log("rete libro avviata ma non verificata: intervento manuale")
            return False
        if self.quarantena.exists():
            # La cattura del Lab 10 sta nella rete bridge: la si conserva prima di
            # cancellare la quarantena (solo i file con il nome del verificatore).
            for pcap in sorted(self.quarantena.glob("verifica-obfs4-*.pcap")):
                try:
                    self.catture.mkdir(exist_ok=True)
                    destinazione = self.catture / pcap.name
                    if destinazione.exists():
                        raise OSError(f"{destinazione} esiste già")
                    shutil.move(str(pcap), destinazione)
                    self.log(f"cattura conservata in {destinazione}")
                except OSError as e:
                    self.log(f"cattura {pcap.name} non conservata ({e}): la quarantena resta")
                    self.giornale.unlink(missing_ok=True)
                    self.fase = "completato"
                    return True
            try:
                shutil.rmtree(self.quarantena)      # provenienza già verificata
            except OSError as e:
                self.log(f"quarantena {self.quarantena} non rimossa ({e}): si può cancellare a mano")
        self.giornale.unlink(missing_ok=True)
        self.fase = "completato"
        self.log("rete libro ripristinata, riavviata e verificata")
        return True


def _sigterm(_signo, _frame):
    raise Interruzione()


def main() -> int:
    signal.signal(signal.SIGTERM, _sigterm)
    codice = Scambio(proteggi_ripristino=True).esegui()
    print(f"[scambio] esito finale {codice}: {DESCRIZIONE[codice]}", flush=True)
    return codice


if __name__ == "__main__":
    sys.exit(main())
