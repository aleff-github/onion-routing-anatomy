# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Test offline di scripts/verify_bridge_lab.py (BR-01, BR-02, BR-03)."""
from __future__ import annotations

import http.client
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

import verify_bridge_lab as vb

# --- strumenti di prova ---------------------------------------------------------------


def pcap(n_pacchetti: int) -> bytes:
    """Una cattura pcap valida (link Ethernet) con n pacchetti fittizi da 60 byte."""
    testa = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    ora = int(time.time())
    corpo = b"".join(struct.pack("<IIII", ora, i, 60, 60) + bytes(60) for i in range(n_pacchetti))
    return testa + corpo


def richiedi(porta: int, percorso: str, metodo: str = "GET"):
    c = http.client.HTTPConnection("127.0.0.1", porta, timeout=5)
    try:
        c.request(metodo, percorso)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        c.close()


class Esito:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class ProcessoFinto:
    """Il processo `docker exec … timeout … tcpdump` visto dal verificatore."""

    def __init__(self, righe, codice=0, non_termina=False):
        self.stderr = iter(righe)
        self.codice, self.non_termina = codice, non_termina
        self.ucciso = False

    def wait(self, timeout=None):
        if self.non_termina and not self.ucciso:
            raise subprocess.TimeoutExpired("tcpdump", timeout)
        return self.codice

    def kill(self):
        self.ucciso = True


class ContainerFinto:
    """Simula il container: tcpdump scrive (o non scrive) la cattura nella cartella di
    prova; curl fa una vera richiesta al server locale; tshark restituisce conteggi dati."""

    def __init__(self, cartella: Path, *, cattura=b"", scrivi=True, eta=0.0, righe=None,
                 codice_tcpdump=0, non_termina=False, avvio_errore=None, conteggi=None,
                 codice_tshark=0, curl=None):
        self.cartella, self.cattura, self.scrivi, self.eta = cartella, cattura, scrivi, eta
        self.righe = righe if righe is not None else [
            "tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n",
            "12 packets captured\n"]
        self.codice_tcpdump, self.non_termina, self.avvio_errore = codice_tcpdump, non_termina, avvio_errore
        self.conteggi = conteggi if conteggi is not None else {"totali": 12, "dati": 6, "tls": 0}
        self.codice_tshark, self.curl = codice_tshark, curl
        self.processo = None
        self.comandi: list[list[str]] = []

    def avvia(self, cmd, utente=None):
        self.comandi.append(cmd)
        if self.avvio_errore:
            raise self.avvio_errore
        destinazione = self.cartella / Path(cmd[cmd.index("-w") + 1]).name
        if self.scrivi:
            destinazione.write_bytes(self.cattura)
            if self.eta:
                vecchio = time.time() - self.eta
                os.utime(destinazione, (vecchio, vecchio))
        self.processo = ProcessoFinto(self.righe, self.codice_tcpdump, self.non_termina)
        return self.processo

    def esegui(self, cmd, timeout=120, utente=None):
        self.comandi.append(cmd)
        if cmd[0] == "curl":
            return self.curl(cmd) if self.curl else curl_locale(cmd)
        if cmd[0] == "tshark":
            if self.codice_tshark:
                return Esito(self.codice_tshark, "", "tshark: The file appears to be damaged")
            filtro = cmd[cmd.index("-Y") + 1]
            chiave = "tls" if filtro == "tls" else "dati" if "tcp.len" in filtro else "totali"
            valore = self.conteggi[chiave]
            if isinstance(valore, str):
                return Esito(0, valore)
            return Esito(0, "".join(f"{i}\n" for i in range(1, valore + 1)))
        if cmd[0] == "pkill":
            return Esito(0)
        raise AssertionError(f"comando inatteso: {cmd}")


def curl_locale(cmd):
    """Come curl --write-out '\\n%{http_code}', ma diretto al server locale (niente Tor)."""
    url = cmd[-1]
    porta = int(url.split(":")[2].split("/")[0])
    try:
        stato, _, corpo = richiedi(porta, "/" + url.split("/", 3)[3])
    except OSError as e:
        return Esito(7, "", f"curl: (7) {e}")
    return Esito(0, corpo.decode() + f"\n{stato}")


# --- BR-02: server HTTP ------------------------------------------------------------


@pytest.fixture
def server():
    with vb.ServerLaboratorio(porta=0) as s:
        yield s


def test_http_200_sul_percorso_previsto(server):
    stato, intestazioni, corpo = richiedi(server.porta, "/")
    assert stato == 200
    assert corpo == server.corpo and server.nonce.encode() in corpo
    assert intestazioni["Content-Type"] == "text/plain; charset=utf-8"
    assert int(intestazioni["Content-Length"]) == len(corpo)


def test_head_senza_corpo(server):
    stato, intestazioni, corpo = richiedi(server.porta, "/", "HEAD")
    assert stato == 200 and corpo == b"" and int(intestazioni["Content-Length"]) == len(server.corpo)


@pytest.mark.parametrize("percorso", ["/index.html", "/README.md", "/Makefile", "/../Makefile",
                                      "/scripts/", "/scripts/verify_bridge_lab.py",
                                      "/labs/it/laboratorio/net/nodes/", "/?x=1", "//etc/passwd", "/%2e%2e/"])
def test_404_sugli_altri_percorsi(server, percorso):
    stato, intestazioni, corpo = richiedi(server.porta, percorso)
    assert stato == 404
    assert corpo == b"Non trovato\n" and int(intestazioni["Content-Length"]) == len(corpo)


def test_nessun_accesso_ai_file_del_repository(server, tmp_path, monkeypatch):
    # Anche con la cartella di lavoro dentro una cartella con file "sensibili", il server
    # non li serve: non legge file e non elenca cartelle.
    (tmp_path / "segreto_ed25519_master_id_secret_key").write_text("CHIAVE")
    monkeypatch.chdir(tmp_path)
    for percorso in ("/", "/segreto_ed25519_master_id_secret_key", "/.", "/./"):
        _, _, corpo = richiedi(server.porta, percorso)
        assert b"CHIAVE" not in corpo and b"segreto" not in corpo
    assert vb.RispostaLaboratorio.__mro__[1] is vb.http.server.BaseHTTPRequestHandler
    assert not issubclass(vb.RispostaLaboratorio, vb.http.server.SimpleHTTPRequestHandler)


def test_ascolta_solo_su_loopback():
    with pytest.raises(ValueError):
        vb.ServerLaboratorio(porta=0, indirizzo="0.0.0.0")
    with vb.ServerLaboratorio(porta=0) as s:
        assert s._server.server_address[0] == "127.0.0.1"


def test_nessun_log_delle_richieste(server, capsys):
    richiedi(server.porta, "/")
    richiedi(server.porta, "/assente")
    catturato = capsys.readouterr()
    assert catturato.out == "" and catturato.err == ""


def test_corpo_diverso_a_ogni_esecuzione():
    with vb.ServerLaboratorio(porta=0) as a, vb.ServerLaboratorio(porta=0) as b:
        assert a.corpo != b.corpo


def _porta_chiusa(porta: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", porta)) != 0


def test_risorse_http_chiuse():
    prima = threading.active_count()
    with vb.ServerLaboratorio(porta=0) as s:
        porta = s.porta
        richiedi(porta, "/")
    assert s._thread is None and s._server.socket.fileno() == -1
    assert _porta_chiusa(porta)
    time.sleep(0.1)
    assert threading.active_count() <= prima


def test_risorse_http_chiuse_anche_con_eccezione():
    with pytest.raises(RuntimeError):
        with vb.ServerLaboratorio(porta=0) as s:
            porta = s.porta
            raise RuntimeError("errore durante la verifica")
    assert _porta_chiusa(porta) and s._thread is None


# --- BR-01: richiesta che genera il traffico -------------------------------------------


def _richiesta(esito_curl, atteso=b"anatomia-di-tor laboratorio-10 abc\n"):
    class C:
        def esegui(self, cmd, timeout=120, utente=None):
            if isinstance(esito_curl, Exception):
                raise esito_curl
            return esito_curl
    return vb.richiesta_attraverso_bridge(C(), "9011", 8080, atteso)


def test_richiesta_corretta():
    assert _richiesta(Esito(0, "anatomia-di-tor laboratorio-10 abc\n\n200"))[0] is True


@pytest.mark.parametrize("esito", [
    Esito(7, "\n000", "curl: (7) Failed to connect"),           # curl fallito
    Esito(97, "\n000", "curl: (97) SOCKS failure"),              # proxy SOCKS
    Esito(18, "anatomia-di-tor laboratorio-10 abc\n\n200", "curl: (18) transfer closed"),  # troncata
    Esito(0, "Non trovato\n\n404"),                              # risposta non 200
    Esito(0, "anatomia-di-tor laboratorio-10 vecchio\n\n200"),   # server di un'altra esecuzione
    Esito(0, "\n200"),                                           # corpo vuoto
    Esito(0, ""),                                                # output vuoto
    subprocess.TimeoutExpired("curl", 90),
    OSError("docker assente"),
])
def test_errore_nella_richiesta_che_genera_traffico(esito):
    ok, dettaglio = _richiesta(esito)
    assert ok is False and dettaglio


def test_richiesta_attraverso_server_reale_della_esecuzione(server, tmp_path):
    c = ContainerFinto(tmp_path)
    ok, dettaglio = vb.richiesta_attraverso_bridge(c, "9011", server.porta, server.corpo)
    assert ok, dettaglio
    # Con il server spento la stessa richiesta deve fallire.
    porta = server.porta
    server.chiudi()
    ok, _ = vb.richiesta_attraverso_bridge(c, "9011", porta, server.corpo)
    assert ok is False


# --- BR-03: cattura ----------------------------------------------------------------


def _cattura(tmp_path, container, traffico=lambda: (True, "ok"), esecuzione="prova"):
    esiti = vb.Esiti()
    ok = vb.cattura_obfs4(container, tmp_path, "9909", traffico, esiti, durata=1,
                          attesa_avvio=0.5, esecuzione=esecuzione)
    return ok, esiti


def _fallito(esiti, prefisso):
    return [n for n, ok, _ in esiti.righe if n.startswith(prefisso) and not ok]


def test_cattura_valida(tmp_path):
    ok, esiti = _cattura(tmp_path, ContainerFinto(tmp_path, cattura=pcap(12)))
    assert ok and esiti.tutti_ok
    import hashlib
    dettaglio = next(d for n, _, d in esiti.righe if n.startswith("Cattura: file presente"))
    scritto = (tmp_path / "verifica-obfs4-prova.pcap").read_bytes()
    assert dettaglio.endswith(f"sha256 {hashlib.sha256(scritto).hexdigest()}")
    assert len(esiti.righe) == 9


def test_avvio_di_tcpdump_fallito(tmp_path):
    c = ContainerFinto(tmp_path, righe=["tcpdump: lo: You don't have permission to capture\n"],
                       codice_tcpdump=1, scrivi=False)
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Cattura: tcpdump avviato")
    assert c.processo.ucciso                                   # processo raccolto
    assert not any(r[0] == "curl" for r in c.comandi)          # nessun traffico senza cattura


def test_avvio_di_docker_impossibile(tmp_path):
    ok, esiti = _cattura(tmp_path, ContainerFinto(tmp_path, avvio_errore=OSError("docker assente")))
    assert not ok and _fallito(esiti, "Cattura: tcpdump avviato")


def test_timeout_di_tcpdump(tmp_path):
    c = ContainerFinto(tmp_path, cattura=pcap(3), non_termina=True)
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Cattura: tcpdump terminato")
    assert c.processo.ucciso and ["pkill", "-INT", "-f", "verifica-obfs4-prova.pcap"] in c.comandi
    assert not any(r[0] == "tshark" for r in c.comandi)        # nessuna analisi


def test_tcpdump_terminato_con_errore(tmp_path):
    ok, esiti = _cattura(tmp_path, ContainerFinto(tmp_path, cattura=pcap(3), codice_tcpdump=1))
    assert not ok and _fallito(esiti, "Cattura: tcpdump terminato")


def test_pcap_mancante(tmp_path):
    c = ContainerFinto(tmp_path, scrivi=False)
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Cattura: file presente")
    assert not any(r[0] == "tshark" for r in c.comandi)


@pytest.mark.parametrize("contenuto", [b"", pcap(0), b"non e' una cattura" * 4])
def test_pcap_vuoto_o_non_valido(tmp_path, contenuto):
    c = ContainerFinto(tmp_path, cattura=contenuto, righe=[
        "tcpdump: listening on lo\n", "0 packets captured\n"])
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Cattura: file presente")
    assert not any(r[0] == "tshark" for r in c.comandi)


def test_pcap_di_una_esecuzione_precedente_con_lo_stesso_nome(tmp_path):
    (tmp_path / "verifica-obfs4-prova.pcap").write_bytes(pcap(50))
    c = ContainerFinto(tmp_path, cattura=pcap(50))
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Cattura: file nuovo")
    assert c.comandi == []                                     # nessun tcpdump avviato


def test_pcap_piu_vecchio_dell_avvio(tmp_path):
    ok, esiti = _cattura(tmp_path, ContainerFinto(tmp_path, cattura=pcap(50), eta=3600))
    assert not ok and _fallito(esiti, "Cattura: file presente")


def test_nomi_di_cattura_diversi_a_ogni_esecuzione(tmp_path):
    a, b = ContainerFinto(tmp_path, cattura=pcap(5)), ContainerFinto(tmp_path, cattura=pcap(5))
    vb.cattura_obfs4(a, tmp_path, "9909", lambda: (True, ""), vb.Esiti(), durata=1, attesa_avvio=0.5)
    vb.cattura_obfs4(b, tmp_path, "9909", lambda: (True, ""), vb.Esiti(), durata=1, attesa_avvio=0.5)
    assert a.comandi[0][a.comandi[0].index("-w") + 1] != b.comandi[0][b.comandi[0].index("-w") + 1]


def test_errore_di_tshark(tmp_path):
    ok, esiti = _cattura(tmp_path, ContainerFinto(tmp_path, cattura=pcap(5), codice_tshark=2))
    assert not ok and _fallito(esiti, "Cattura: analisi tshark")


def test_output_di_tshark_non_numerico(tmp_path):
    c = ContainerFinto(tmp_path, cattura=pcap(5), conteggi={"totali": "1\nerrore\n", "dati": 1, "tls": 0})
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Cattura: analisi tshark")


def test_cattura_valida_senza_traffico_obfs4(tmp_path):
    c = ContainerFinto(tmp_path, cattura=pcap(4), conteggi={"totali": 0, "dati": 0, "tls": 0})
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Lab 10: la cattura sulla porta obfs4 contiene traffico")


def test_solo_handshake_tcp_senza_dati(tmp_path):
    c = ContainerFinto(tmp_path, cattura=pcap(4), conteggi={"totali": 4, "dati": 0, "tls": 0})
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Lab 10: la cattura sulla porta obfs4 contiene traffico")


@pytest.mark.parametrize("conteggi", [{"totali": 3, "dati": 2, "tls": 5},
                                      {"totali": 3, "dati": 7, "tls": 0}])
def test_risultato_tls_incoerente(tmp_path, conteggi):
    ok, esiti = _cattura(tmp_path, ContainerFinto(tmp_path, cattura=pcap(3), conteggi=conteggi))
    assert not ok and _fallito(esiti, "Cattura: risultati coerenti")


def test_traffico_riconosciuto_come_tls(tmp_path):
    c = ContainerFinto(tmp_path, cattura=pcap(9), conteggi={"totali": 9, "dati": 5, "tls": 2})
    ok, esiti = _cattura(tmp_path, c)
    assert not ok and _fallito(esiti, "Lab 10: nessun pacchetto della cattura riconosciuto come TLS")


def test_richiesta_di_traffico_fallita_durante_la_cattura(tmp_path):
    c = ContainerFinto(tmp_path, cattura=pcap(5))
    ok, esiti = _cattura(tmp_path, c, traffico=lambda: (False, "HTTP 404"))
    assert not ok and _fallito(esiti, "Cattura: richiesta di traffico")
    assert not any(r[0] == "tshark" for r in c.comandi)        # niente PASS sul TLS


def test_eccezione_nella_richiesta_di_traffico(tmp_path):
    def esplode():
        raise ConnectionResetError("reset")
    ok, esiti = _cattura(tmp_path, ContainerFinto(tmp_path, cattura=pcap(5)), traffico=esplode)
    assert not ok and _fallito(esiti, "Cattura: richiesta di traffico")


# --- verifica completa e codice di uscita ---------------------------------------------------


def _nodi(tmp_path, bootstrap=True):
    nodi = tmp_path / "nodes"
    (nodi / "011bc").mkdir(parents=True)
    (nodi / "009br").mkdir()
    (nodi / "011bc" / "torrc").write_text("SocksPort 9011\nUseBridges 1\n")
    (nodi / "011bc" / "notice.log").write_text(
        "[notice] new bridge descriptor 'test009br'\n" + ("[notice] Bootstrapped 100% (done): Done\n"
                                                          if bootstrap else ""))
    (nodi / "009br" / "torrc").write_text("ServerTransportListenAddr obfs4 127.0.0.1:9909\n")
    return nodi


def test_verifica_completa_14_controlli(tmp_path):
    nodi = _nodi(tmp_path)
    c = ContainerFinto(tmp_path, cattura=pcap(12))
    esiti = vb.verifica(nodi, container=c, porta_web=0, durata=1, attesa_avvio=0.5)
    assert esiti.tutti_ok, esiti.righe
    assert len(esiti.righe) == 14
    assert sum(1 for r in c.comandi if r[0] == "curl") == 2     # entrambe con il server attivo


def test_verifica_senza_bootstrap_fallisce(tmp_path):
    esiti = vb.verifica(_nodi(tmp_path, bootstrap=False), container=ContainerFinto(tmp_path, cattura=pcap(12)),
                        porta_web=0, durata=1, attesa_avvio=0.5)
    assert not esiti.tutti_ok


def test_verifica_senza_nodi_bridge(tmp_path):
    (tmp_path / "nodes").mkdir()
    esiti = vb.verifica(tmp_path / "nodes", container=ContainerFinto(tmp_path), porta_web=0)
    assert not esiti.tutti_ok and len(esiti.righe) == 1


def test_server_chiuso_anche_se_la_verifica_si_interrompe(tmp_path, monkeypatch):
    creati = []
    originale = vb.ServerLaboratorio

    class Registrato(originale):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            creati.append(self)

    monkeypatch.setattr(vb, "ServerLaboratorio", Registrato)
    c = ContainerFinto(tmp_path, avvio_errore=RuntimeError("guasto imprevisto"))
    with pytest.raises(RuntimeError):
        vb.verifica(_nodi(tmp_path), container=c, porta_web=0, durata=1, attesa_avvio=0.5)
    assert creati and _porta_chiusa(creati[0].porta) and creati[0]._thread is None


def test_codice_di_uscita_del_verificatore(monkeypatch, capsys):
    tutti = vb.Esiti()
    tutti.controlla("a", True)
    uno_fallito = vb.Esiti()
    uno_fallito.controlla("a", True)
    uno_fallito.controlla("b", False)

    monkeypatch.setattr(vb, "verifica", lambda: tutti)
    assert vb.main() == 0
    monkeypatch.setattr(vb, "verifica", lambda: uno_fallito)
    assert vb.main() == 1
    monkeypatch.setattr(vb, "verifica", lambda: vb.Esiti())     # nessun controllo: non è un PASS
    assert vb.main() == 1

    def esplode():
        raise FileNotFoundError("torrc")
    monkeypatch.setattr(vb, "verifica", esplode)
    assert vb.main() == 1
    assert "verifica interrotta" in capsys.readouterr().out
