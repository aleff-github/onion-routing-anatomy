# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Test offline di scripts/swap_bridge_network.py (BR-04) e dei target make collegati.

Il container è simulato: le cartelle net/, net-libro/ e la quarantena sono vere (in una
cartella temporanea), i comandi docker e i verificatori no.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

import swap_bridge_network as sr

RADICE = Path(__file__).resolve().parents[2]
LIBRO = {"000a": "AAAA0000", "001a": "AAAA0001", "002a": "AAAA0002", "003r": "RRRR0003",
         "006e": "EEEE0006", "008c": "CCCC0008", "009h": "HHHH0009"}
BRIDGE = {"000a": "BA000000", "003ba": "BA000003", "009br": "BR000009", "011bc": "BC000011"}


def crea_rete(net: Path, impronte: dict[str, str], istante: str, link_assoluto=False) -> None:
    for nome, fp in impronte.items():
        d = net / f"nodes.{istante}" / nome
        d.mkdir(parents=True)
        (d / "fingerprint").write_text(f"test{nome} {fp}\n")
        torrc = "# torrc\n"
        if nome.endswith("br"):
            torrc += "ServerTransportListenAddr obfs4 127.0.0.1:9909\n"
        (d / "torrc").write_text(torrc)
    (net / "nodes").symlink_to(f"/lab/net/nodes.{istante}" if link_assoluto else f"nodes.{istante}")


def stato(lab: Path) -> dict:
    """Istantanea di ciò che conta: quali cartelle esistono e con quali impronte."""
    return {p.name: sr.impronte(p) for p in sorted(lab.iterdir()) if p.is_dir()}


def ss(*voci) -> str:
    return "".join(f"LISTEN 0 4096 {ind} 0.0.0.0:* users:((\"{proc}\",pid=1,fd=3))\n" for ind, proc in voci)


ASCOLTI_BRIDGE = ss(("127.0.0.1:5100", "tor"), ("127.0.0.1:7100", "tor"), ("127.0.0.1:9500", "tor"),
                    ("127.0.0.1:9909", "obfs4proxy"), ("127.0.0.1:41234", "obfs4proxy"))
ASCOLTI_LIBRO = ss(("127.0.0.1:5100", "tor"), ("127.0.0.1:7100", "tor"), ("127.0.0.1:9008", "tor"))


class Finto(sr.Comandi):
    """Container e host simulati. Ogni comportamento si altera con gli argomenti."""

    def __init__(self, lab: Path, *, ambiente=0, tor_non_si_ferma=False, init=0, init_crea=True,
                 init_impronte=None, bootstrap=0, verifica=0, start=0, wait=0, durante_verifica=None,
                 bridge_non_si_ferma=False, obfs4_non_si_ferma=False, pgrep_rotto=False,
                 verify_fallimenti=0, ascolti_bridge=ASCOLTI_BRIDGE, ascolti_libro=ASCOLTI_LIBRO,
                 conteggio_tor=None, zombie=False, verify_esiti=None):
        self.lab, self.ambiente, self.tor_non_si_ferma = lab, ambiente, tor_non_si_ferma
        self.init, self.init_crea, self.init_impronte = init, init_crea, init_impronte or BRIDGE
        self.bootstrap, self.verifica, self.start, self.wait = bootstrap, verifica, start, wait
        self.durante_verifica = durante_verifica
        self.bridge_non_si_ferma, self.obfs4_non_si_ferma = bridge_non_si_ferma, obfs4_non_si_ferma
        self.pgrep_rotto, self.docker_rotto = pgrep_rotto, False
        self.verify_fallimenti = verify_fallimenti          # -1: sempre
        self.ascolti_bridge, self.ascolti_libro, self.conteggio_tor = ascolti_bridge, ascolti_libro, conteggio_tor
        self.tor, self.obfs4 = True, False
        self.zombie = zombie            # i tor fermati restano «Z» (container senza --init)
        self.zombie_presenti = 0
        self.verify_eseguiti = 0
        self.verify_esiti = list(verify_esiti or [])     # sequenza di esiti, poi successo
        self.chiamate: list[tuple[str, ...]] = []

    def _nodi(self) -> int:
        return len(list((self.lab / "net" / "nodes").glob("*/torrc")))

    def _rete_bridge(self) -> bool:
        return "009br" in sr.impronte(self.lab / "net") if (self.lab / "net").exists() else False

    def docker(self, *args, timeout=120, env=None):
        self.chiamate.append(args)
        if self.docker_rotto:
            raise FileNotFoundError("docker")
        ok = lambda out="", codice=0: sr.subprocess.CompletedProcess(args, codice, out, "")
        comando = args[2] if args[0] == "sh" else ""
        if args[:2] == ("chutney", "stop") or "pkill" in comando:
            bridge = self._rete_bridge()
            if not self.tor_non_si_ferma and not (bridge and self.bridge_non_si_ferma):
                if self.tor and self.zombie:
                    self.zombie_presenti += self._nodi()
                self.tor = False
            if not self.obfs4_non_si_ferma:
                self.obfs4 = False
            return ok()
        if "ps -eo" in comando:
            if self.pgrep_rotto:
                return ok("ps: errore\nps=1\n")
            vivi = (self.conteggio_tor if self.conteggio_tor is not None else self._nodi()) if self.tor else 0
            righe = ["Ss sleep"] + ["S tor"] * vivi + ["Z tor"] * self.zombie_presenti
            righe += ["S obfs4proxy"] if self.obfs4 else []
            return ok("\n".join(righe) + "\nps=0\n")
        if "chutney verify" in comando:
            self.verify_eseguiti += 1
            riesce = self.verify_esiti.pop(0) if self.verify_esiti else True
            if not riesce or self.verify_fallimenti == -1 or self.verify_eseguiti <= self.verify_fallimenti:
                return ok("not-done:0 successes:2 failures:2\nTransmission: Failure\n", 2)
            return ok("not-done:0 successes:4 failures:0\nTransmission: Success\n")
        if args[:2] == ("ss", "-ltnpH"):
            return ok(self.ascolti_bridge if self._rete_bridge() else self.ascolti_libro)
        if args[:2] == ("chutney", "init"):
            assert not (self.lab / "net").exists(), "init sopra una rete esistente"
            if self.init_crea:
                crea_rete(self.lab / "net", self.init_impronte, "2", link_assoluto=True)
            return sr.subprocess.CompletedProcess(args, self.init, "", "errore" if self.init else "")
        if args[:2] == ("chutney", "bootstrap"):
            self.tor, self.obfs4 = True, True
            return ok(codice=self.bootstrap)
        if args[:2] == ("chutney", "start"):
            self.tor = True
            return ok(codice=self.start)
        if args[:2] == ("chutney", "wait_for_bootstrap"):
            return ok(codice=self.wait)
        raise AssertionError(f"comando inatteso: {args}")

    def host(self, *args, timeout=900):
        self.chiamate.append(("host",) + args)
        if "--controlla-ambiente" in args:
            return sr.subprocess.CompletedProcess(args, self.ambiente)
        assert args[1] == "scripts/verify_bridge_lab.py"
        # Durante la verifica: rete libro da parte, rete bridge in net/ con il marcatore.
        assert sr.impronte(self.lab / "net-libro") == {k: f"test{k} {v}" for k, v in LIBRO.items()}
        assert "009br" in sr.impronte(self.lab / "net")
        assert (self.lab / "net" / "nodes").resolve() == (self.lab / "net" / "nodes.2").resolve()
        if self.durante_verifica:
            self.durante_verifica(self)
        if isinstance(self.verifica, BaseException):
            raise self.verifica
        return sr.subprocess.CompletedProcess(args, self.verifica)


@pytest.fixture
def lab(tmp_path):
    crea_rete(tmp_path / "net", LIBRO, "1")
    (tmp_path / "net" / "nodes.1" / "003r" / "pid").write_text("123\n")
    (tmp_path / "net" / "nodes.1" / "003r" / "keys").mkdir()
    (tmp_path / "net" / "nodes.1" / "003r" / "keys" / "secret_id_key").write_text("CHIAVE-003r\n")
    return tmp_path


def esegui(lab, attesa_salute=0, successi_salute=1, **opzioni):
    finto = Finto(lab, **opzioni)
    codice = sr.Scambio(lab=lab, comandi=finto, attesa_arresto=0, attesa_salute=attesa_salute,
                        intervallo_salute=0, successi_salute=successi_salute).esegui()
    return codice, finto


def libro_intatta_e_ripartita(lab, finto) -> bool:
    return (sr.impronte(lab / "net") == {k: f"test{k} {v}" for k, v in LIBRO.items()}
            and not (lab / "net-libro").exists()
            and not list(lab.glob("net-bridge-*"))
            and not (lab / "verifica-bridge.stato").exists()
            and ("chutney", "wait_for_bootstrap") in finto.chiamate
            and finto.verify_eseguiti >= 1
            and not list((lab / "net" / "nodes").glob("*/pid")))


def ferma_in_attesa_di_intervento(lab) -> bool:
    """Codice 3 senza spostamenti nel ripristino: rete bridge in net/, libro in net-libro/."""
    return ((lab / "verifica-bridge.stato").exists() and (lab / "net-libro").is_dir()
            and (lab / "net" / "nodes.2" / "009br").is_dir() and not list(lab.glob("net-bridge-*")))


# --- esiti normali ------------------------------------------------------------------


def test_successo(lab):
    codice, finto = esegui(lab)
    assert codice == sr.OK and libro_intatta_e_ripartita(lab, finto)
    assert (lab / "esito-bridge").read_text() == "0\n"


def test_controlli_del_bridge_falliti(lab):
    codice, finto = esegui(lab, verifica=1)
    assert codice == sr.CONTROLLI_FALLITI and libro_intatta_e_ripartita(lab, finto)
    assert (lab / "esito-bridge").read_text() == "1\n"


@pytest.mark.parametrize("errore", [OSError("python assente"), RuntimeError("guasto"),
                                    subprocess.TimeoutExpired("verify_bridge_lab.py", 900),
                                    KeyboardInterrupt(), sr.Interruzione()])
def test_verificatore_python_fallito_o_interrotto(lab, errore):
    codice, finto = esegui(lab, verifica=errore)
    assert codice == sr.CONTROLLI_FALLITI and libro_intatta_e_ripartita(lab, finto)


def test_bootstrap_incompleto_non_ferma_il_ripristino(lab):
    codice, finto = esegui(lab, bootstrap=1, verifica=1)
    assert codice == sr.CONTROLLI_FALLITI and libro_intatta_e_ripartita(lab, finto)


def test_esito_di_una_esecuzione_precedente_non_viene_riusato(lab):
    (lab / "esito-bridge").write_text("0\n")
    codice, _ = esegui(lab, init=1)
    assert codice == sr.CONTROLLI_FALLITI and not (lab / "esito-bridge").exists()


# --- creazione della rete bridge fallita ----------------------------------------------------


def test_init_del_bridge_fallito_senza_cartella(lab):
    codice, finto = esegui(lab, init=1, init_crea=False)
    assert codice == sr.CONTROLLI_FALLITI and libro_intatta_e_ripartita(lab, finto)
    assert not any(c[0] == "host" and "verify_bridge_lab.py" in c for c in finto.chiamate)


def test_init_del_bridge_fallito_a_meta(lab):
    # net/ creata in parte, senza marcatore: provenienza dimostrata dalla fase registrata e
    # dall'assenza di impronte della rete libro; finisce in quarantena e poi viene rimossa.
    codice, finto = esegui(lab, init=1)
    assert codice == sr.CONTROLLI_FALLITI and libro_intatta_e_ripartita(lab, finto)


def test_init_fallito_con_impronte_della_rete_libro_non_cancella(lab):
    sospette = dict(BRIDGE, **{"003r": LIBRO["003r"]})
    codice, _ = esegui(lab, init=1, init_impronte=sospette)
    assert codice == sr.RIPRISTINO_FALLITO
    # Nulla è stato cancellato o spostato oltre: la rete libro è ancora in net-libro/.
    assert sr.impronte(lab / "net-libro")["003r"].endswith(LIBRO["003r"])
    assert (lab / "net" / "nodes.2" / "003r" / "fingerprint").is_file()
    assert (lab / "verifica-bridge.stato").exists()


# --- controlli preliminari: nessuna modifica -----------------------------------------------


def test_net_libro_residua(lab):
    (lab / "net-libro" / "nodes").mkdir(parents=True)
    prima = stato(lab)
    codice, finto = esegui(lab)
    assert codice == sr.NON_ESEGUITO and stato(lab) == prima and finto.chiamate == []


def test_giornale_di_una_esecuzione_interrotta(lab):
    (lab / "verifica-bridge.stato").write_text('{"fase": "verifica-bridge"}')
    prima = stato(lab)
    codice, finto = esegui(lab)
    assert codice == sr.NON_ESEGUITO and stato(lab) == prima and finto.chiamate == []


def test_rete_libro_assente(tmp_path):
    codice, finto = esegui(tmp_path)
    assert codice == sr.NON_ESEGUITO and finto.chiamate == [] and list(tmp_path.iterdir()) == []


def test_controllo_ambiente_fallito(lab):
    prima = stato(lab)
    codice, finto = esegui(lab, ambiente=1)
    assert codice == sr.NON_ESEGUITO and stato(lab) == prima
    assert all(c[0] == "host" for c in finto.chiamate)          # nessun comando nel container
    assert not (lab / "verifica-bridge.stato").exists()


def test_tor_non_si_ferma(lab):
    """BR-05: arresto della rete libro non confermato -> nessuno spostamento e codice 3
    (la rete può essere stata fermata solo in parte: lo si dice, non lo si indovina)."""
    prima = stato(lab)
    codice, finto = esegui(lab, tor_non_si_ferma=True)
    assert codice == sr.RIPRISTINO_FALLITO and stato(lab) == prima
    assert (lab / "verifica-bridge.stato").exists()
    assert not any(c[:2] == ("chutney", "init") for c in finto.chiamate)


# --- BR-05: ripristino solo ad arresto confermato e rete verificata ------------------------


def test_bridge_non_si_ferma_nessuno_spostamento(lab):
    codice, finto = esegui(lab, bridge_non_si_ferma=True)
    assert codice == sr.RIPRISTINO_FALLITO and ferma_in_attesa_di_intervento(lab)
    assert not any(c[:2] == ("chutney", "start") for c in finto.chiamate)


def test_obfs4proxy_ancora_attivo_nessuno_spostamento(lab):
    codice, _ = esegui(lab, obfs4_non_si_ferma=True)
    assert codice == sr.RIPRISTINO_FALLITO and ferma_in_attesa_di_intervento(lab)


def test_docker_non_disponibile_durante_il_ripristino(lab):
    def rompi(finto):
        finto.docker_rotto = True
    codice, _ = esegui(lab, durante_verifica=rompi)
    assert codice == sr.RIPRISTINO_FALLITO and ferma_in_attesa_di_intervento(lab)


def test_tor_zombie_non_impediscono_lo_scambio(lab):
    """Prima validazione reale del Lab 10 (28/10/2026): nel container senza --init i tor
    fermati restano zombie; contano solo i processi vivi."""
    codice, finto = esegui(lab, zombie=True)
    assert finto.zombie_presenti > 0
    assert codice == sr.OK and libro_intatta_e_ripartita(lab, finto)


def test_errore_di_ps_non_vale_come_rete_ferma(lab):
    def rompi(finto):
        finto.pgrep_rotto = True
    codice, _ = esegui(lab, durante_verifica=rompi)
    assert codice == sr.RIPRISTINO_FALLITO and ferma_in_attesa_di_intervento(lab)


def test_bootstrap_riuscito_ma_chutney_verify_fallito(lab):
    codice, finto = esegui(lab, verify_fallimenti=-1)
    assert codice == sr.RIPRISTINO_FALLITO
    assert sr.impronte(lab / "net") == {k: f"test{k} {v}" for k, v in LIBRO.items()}
    assert (lab / "verifica-bridge.stato").exists() and finto.verify_eseguiti == 1


def test_onion_service_in_ritardo_attesa_limitata(lab):
    """chutney verify fallisce due volte (onion service non ancora raggiungibile), poi riesce
    entro l'attesa: ripristino verificato."""
    codice, finto = esegui(lab, attesa_salute=30, verify_fallimenti=2)
    assert codice == sr.OK and libro_intatta_e_ripartita(lab, finto) and finto.verify_eseguiti == 3


def test_un_solo_successo_di_chutney_verify_non_basta(lab):
    """Come nell'esecuzione reale 3: successo, poi fallimenti (onion service), poi stabile.
    Con i valori predefiniti (3 di fila) la rete è sana solo dopo tre successi consecutivi."""
    codice, finto = esegui(lab, attesa_salute=60, successi_salute=3,
                           verify_esiti=[True, False, False, True, True, True])
    assert codice == sr.OK and finto.verify_eseguiti == 6 and libro_intatta_e_ripartita(lab, finto)


def test_successi_alternati_rete_non_sana(lab):
    codice, finto = esegui(lab, attesa_salute=0.2, successi_salute=3,
                           verify_esiti=[True, False] * 10000)
    assert codice == sr.RIPRISTINO_FALLITO and (lab / "verifica-bridge.stato").exists()


def test_valori_predefiniti_della_salute():
    s = sr.Scambio(lab=Path("/inesistente"), comandi=sr.Comandi())
    assert (s.attesa_salute, s.intervallo_salute, s.successi_salute) == (720, 30, 3)


def test_numero_di_processi_tor_sbagliato(lab):
    codice, _ = esegui(lab, conteggio_tor=9)
    assert codice == sr.RIPRISTINO_FALLITO and (lab / "verifica-bridge.stato").exists()


def test_chiave_privata_modificata_durante_la_prova(lab):
    def altera(finto):
        (lab / "net-libro" / "nodes" / "003r" / "keys" / "secret_id_key").write_text("ALTRA\n")
    codice, finto = esegui(lab, durante_verifica=altera)
    assert codice == sr.RIPRISTINO_FALLITO and (lab / "verifica-bridge.stato").exists()
    assert not any(c[:2] == ("chutney", "start") for c in finto.chiamate)   # non riavviata


def test_torrc_modificato_durante_la_prova(lab):
    def altera(finto):
        (lab / "net-libro" / "nodes" / "008c" / "torrc").write_text("# torrc\nSocksPort 0.0.0.0:9008\n")
    codice, _ = esegui(lab, durante_verifica=altera)
    assert codice == sr.RIPRISTINO_FALLITO


def test_ascolti_della_rete_libro_non_confinati_dopo_il_riavvio(lab):
    codice, _ = esegui(lab, ascolti_libro=ss(("0.0.0.0:7100", "tor")))
    assert codice == sr.RIPRISTINO_FALLITO


# --- BR-06: isolamento della rete bridge prima del traffico ------------------------------------


@pytest.mark.parametrize("ascolti", [
    ss(("0.0.0.0:9909", "obfs4proxy")),                                     # obfs4 su tutte le interfacce
    ss(("127.0.0.1:9909", "obfs4proxy"), ("[::]:9909", "obfs4proxy")),      # anche su IPv6
    ss(("127.0.0.1:9909", "obfs4proxy"), ("0.0.0.0:7103", "tor")),          # DirPort di un relay
    ss(("127.0.0.1:9909", "obfs4proxy"), ("*:9500", "tor")),                # ExtORPort
    ss(("127.0.0.1:5100", "tor")),                                          # obfs4proxy non in ascolto
])
def test_isolamento_bridge_violato_prova_interrotta(lab, ascolti):
    codice, finto = esegui(lab, ascolti_bridge=ascolti)
    assert codice == sr.CONTROLLI_FALLITI and libro_intatta_e_ripartita(lab, finto)
    assert not any(c[0] == "host" and "scripts/verify_bridge_lab.py" in c for c in finto.chiamate)


def test_isolamento_bridge_verificato_prima_della_verifica(lab):
    codice, finto = esegui(lab)
    ss_bridge = next(i for i, c in enumerate(finto.chiamate) if c[:2] == ("ss", "-ltnpH"))
    verifica = next(i for i, c in enumerate(finto.chiamate) if c[0] == "host" and "scripts/verify_bridge_lab.py" in c)
    assert codice == sr.OK and ss_bridge < verifica


# --- ripristino fallito: codice 3, niente cancellato ------------------------------------------


def test_ripristino_fallito_la_rete_libro_non_riparte(lab):
    codice, finto = esegui(lab, start=1)
    assert codice == sr.RIPRISTINO_FALLITO
    assert sr.impronte(lab / "net") == {k: f"test{k} {v}" for k, v in LIBRO.items()}
    assert (lab / "verifica-bridge.stato").exists()             # resta il segnale per la guardia
    giornale = json.loads((lab / "verifica-bridge.stato").read_text())
    assert giornale["fase"] == "libro-ripristinata"


def test_ripristino_fallito_anche_se_i_controlli_passano(lab):
    codice, _ = esegui(lab, verifica=0, wait=1)
    assert codice == sr.RIPRISTINO_FALLITO


def test_net_libro_scomparsa_durante_la_verifica(lab, tmp_path_factory):
    altrove = tmp_path_factory.mktemp("altrove")

    def sposta(finto):
        shutil.move(str(lab / "net-libro"), str(altrove / "net-libro"))

    codice, _ = esegui(lab, durante_verifica=sposta)
    assert codice == sr.RIPRISTINO_FALLITO
    assert "009br" in sr.impronte(lab / "net")                  # la rete bridge non è cancellata


def test_impronte_cambiate_durante_la_verifica(lab):
    def altera(finto):
        (lab / "net-libro" / "nodes" / "003r" / "fingerprint").write_text("test003r ALTRA\n")

    codice, _ = esegui(lab, durante_verifica=altera)
    assert codice == sr.RIPRISTINO_FALLITO
    assert (lab / "verifica-bridge.stato").exists()


def test_net_estranea_comparsa_al_posto_della_rete_bridge(lab):
    def sostituisci(finto):
        shutil.rmtree(lab / "net")
        (lab / "net").mkdir()
        (lab / "net" / "dati-di-qualcun-altro").write_text("x")

    codice, _ = esegui(lab, durante_verifica=sostituisci)
    assert codice == sr.RIPRISTINO_FALLITO
    assert (lab / "net" / "dati-di-qualcun-altro").exists()     # non toccata
    assert (lab / "net-libro").is_dir()


# --- segnali --------------------------------------------------------------------------------


def test_sigterm_durante_la_verifica(lab):
    precedente = signal.signal(signal.SIGTERM, sr._sigterm)
    try:
        codice, finto = esegui(lab, durante_verifica=lambda f: os.kill(os.getpid(), signal.SIGTERM))
    finally:
        signal.signal(signal.SIGTERM, precedente)
    assert codice == sr.CONTROLLI_FALLITI and libro_intatta_e_ripartita(lab, finto)


def test_ctrl_c_ignorato_durante_il_ripristino(lab):
    finto = Finto(lab)
    originale = finto.docker

    def docker(*args, **k):
        if args[:2] == ("chutney", "wait_for_bootstrap"):
            os.kill(os.getpid(), signal.SIGINT)                 # Ctrl-C a metà ripristino
        return originale(*args, **k)

    finto.docker = docker
    codice = sr.Scambio(lab=lab, comandi=finto, attesa_arresto=0, proteggi_ripristino=True,
                         attesa_salute=0, intervallo_salute=0, successi_salute=1).esegui()
    assert codice == sr.OK and libro_intatta_e_ripartita(lab, finto)
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


def test_errore_di_docker_non_sembra_una_rete_ferma_prima(lab):
    class SenzaDocker(Finto):
        def docker(self, *args, timeout=120, env=None):
            raise FileNotFoundError("docker")

    finto = SenzaDocker(lab)
    prima = stato(lab)
    codice = sr.Scambio(lab=lab, comandi=finto, attesa_arresto=0).esegui()
    assert codice == sr.RIPRISTINO_FALLITO and stato(lab) == prima   # nulla spostato


# --- codici di uscita fino a make -----------------------------------------------------------


@pytest.mark.parametrize("codice", [0, 1, 2, 3])
def test_main_restituisce_il_codice(monkeypatch, capsys, codice):
    monkeypatch.setattr(sr.Scambio, "esegui", lambda self: codice)
    monkeypatch.setattr(sr.signal, "signal", lambda *a: None)
    assert sr.main() == codice
    assert f"esito finale {codice}" in capsys.readouterr().out


@pytest.fixture
def docker_finto(tmp_path):
    """Un `docker` nel PATH che registra le chiamate e fallisce: make non deve usarlo."""
    cartella = tmp_path / "bin"
    cartella.mkdir()
    registro = tmp_path / "docker.log"
    (cartella / "docker").write_text(f'#!/bin/sh\necho "$@" >> {registro}\nexit 99\n')
    (cartella / "docker").chmod(0o755)
    return {"PATH": f"{cartella}:{os.environ['PATH']}"}, registro


@pytest.mark.parametrize("codice", [0, 1, 2, 3])
def test_make_propaga_il_codice_di_uscita(tmp_path, docker_finto, codice):
    env, registro = docker_finto
    copia = tmp_path / "repo"
    (copia / "scripts").mkdir(parents=True)
    shutil.copy(RADICE / "Makefile", copia / "Makefile")
    (copia / "scripts" / "swap_bridge_network.py").write_text(f"import sys\nsys.exit({codice})\n")
    r = subprocess.run(["make", "-s", "verifica-lab-bridge"], cwd=copia, env={**os.environ, **env},
                       capture_output=True, text=True, timeout=60)
    assert (r.returncode == 0) == (codice == 0)
    if codice:
        assert f"Error {codice}" in r.stderr
    assert not registro.exists()


def test_make_con_lo_script_vero_senza_rete(tmp_path, docker_finto):
    env, registro = docker_finto
    copia = tmp_path / "repo"
    (copia / "scripts").mkdir(parents=True)
    (copia / "labs" / "it" / "laboratorio").mkdir(parents=True)
    shutil.copy(RADICE / "Makefile", copia / "Makefile")
    shutil.copy(RADICE / "scripts" / "swap_bridge_network.py", copia / "scripts")
    shutil.copy(RADICE / "scripts" / "loopback_network.py", copia / "scripts")
    r = subprocess.run(["make", "-s", "verifica-lab-bridge"], cwd=copia, env={**os.environ, **env},
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "Error 2" in r.stderr and "esito finale 2" in r.stdout
    assert not registro.exists() and list((copia / "labs" / "it" / "laboratorio").iterdir()) == []


@pytest.mark.parametrize("residuo", ["verifica-bridge.stato", "net-libro"])
@pytest.mark.parametrize("target", ["avvia", "pulisci"])
def test_guardia_del_makefile_del_laboratorio(tmp_path, docker_finto, residuo, target):
    env, registro = docker_finto
    shutil.copy(RADICE / "labs" / "it" / "laboratorio" / "Makefile", tmp_path / "Makefile")
    (tmp_path / "net").mkdir()
    (tmp_path / residuo).mkdir() if residuo == "net-libro" else (tmp_path / residuo).write_text("{}")
    r = subprocess.run(["make", "-s", target], cwd=tmp_path, env={**os.environ, **env},
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "interrotto" in r.stdout
    assert not registro.exists() and (tmp_path / "net").is_dir()


# --- evidenze: la cattura del Lab 10 non si perde con la quarantena --------------------------


def _scrivi_cattura(finto):
    (finto.lab / "net" / "verifica-obfs4-prova.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + bytes(40))


def test_cattura_conservata_dopo_il_ripristino(lab):
    codice, finto = esegui(lab, durante_verifica=_scrivi_cattura)
    assert codice == sr.OK and libro_intatta_e_ripartita(lab, finto)
    assert (lab / "catture" / "verifica-obfs4-prova.pcap").read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"


def test_cattura_mai_cancellata_se_il_ripristino_fallisce(lab):
    codice, _ = esegui(lab, durante_verifica=_scrivi_cattura, verify_fallimenti=-1)
    assert codice == sr.RIPRISTINO_FALLITO
    assert len(list(lab.glob("net-bridge-*/verifica-obfs4-prova.pcap"))) == 1


def test_cattura_omonima_gia_presente_non_sovrascritta(lab):
    (lab / "catture").mkdir()
    (lab / "catture" / "verifica-obfs4-prova.pcap").write_bytes(b"PRECEDENTE")
    codice, _ = esegui(lab, durante_verifica=_scrivi_cattura)
    assert codice == sr.OK and (lab / "catture" / "verifica-obfs4-prova.pcap").read_bytes() == b"PRECEDENTE"
    assert len(list(lab.glob("net-bridge-*/verifica-obfs4-prova.pcap"))) == 1   # resta in quarantena
