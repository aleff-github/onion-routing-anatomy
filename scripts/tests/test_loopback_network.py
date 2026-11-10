# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""DirPort su loopback, ascolti reali e migrazione dei torrc (offline)."""
from __future__ import annotations

import re
from pathlib import Path

import loopback_network as rl

LAB = Path(__file__).resolve().parents[2] / "labs" / "it" / "laboratorio"

TORRC_EXIT = """TestingTorNetwork 1
DataDirectory /lab/net/nodes.1/006e
Nickname test006e
ControlPort 127.0.0.1:8006
Address 127.0.0.1
OrPort 127.0.0.1:5106
DirAuthority test000a no-v2 orport=5100 v3ident=AAAA 127.0.0.1:7100 BBBB

DirPort 7106
ExitRelay 1
ServerDNSDetectHijacking 0
ServerDNSTestAddresses
ServerDNSResolvConfFile /etc/resolv.conf
ExitPolicy accept *:*
"""

PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13EC 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 00000000:1BBC 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1
   2: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 3 1
   3: 0100007F:14B4 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1
"""
PROC_TCP6 = """  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1BBD 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000001000000:1F40 00000000000000000000000000000000:0000 0A
"""


def test_migrazione_cambia_solo_dirport_e_dns():
    dopo = rl.migra(TORRC_EXIT)
    diverse = [(a, b) for a, b in zip(TORRC_EXIT.splitlines(), dopo.splitlines()) if a != b]
    assert diverse == [("DirPort 7106", "DirPort 127.0.0.1:7106"),
                       ("ServerDNSResolvConfFile /etc/resolv.conf",
                        "ServerDNSResolvConfFile /lab/dns_locale.conf")]
    assert len(dopo.splitlines()) == len(TORRC_EXIT.splitlines())


def test_migrazione_preserva_identita_e_percorsi():
    dopo = rl.migra(TORRC_EXIT)
    for chiave in ("DataDirectory", "Nickname", "DirAuthority", "OrPort", "ControlPort", "Address"):
        assert re.findall(rf"^{chiave} .*$", dopo, re.M) == re.findall(rf"^{chiave} .*$", TORRC_EXIT, re.M)


def test_migrazione_idempotente_e_dirport_zero_invariato():
    assert rl.migra(rl.migra(TORRC_EXIT)) == rl.migra(TORRC_EXIT)
    assert rl.migra("DirPort 0\n") == "DirPort 0\n"
    assert rl.migra("DirPort 127.0.0.1:7100\n") == "DirPort 127.0.0.1:7100\n"


def test_configurazione_dei_dirport():
    assert rl.problemi_torrc("006e", TORRC_EXIT) == [
        "006e: DirPort 7106 non è su 127.0.0.1 (indirizzo tutte le interfacce)",
        "006e: exit senza ServerDNSResolvConfFile /lab/dns_locale.conf"]
    assert rl.problemi_torrc("006e", rl.migra(TORRC_EXIT)) == []
    assert rl.porte_torrc("SocksPort 0\nDirPort 0\nSocksPort 127.0.0.1:9008\n") == [("SocksPort", "127.0.0.1", 9008)]
    assert rl.problemi_torrc("x", "ControlPort 0.0.0.0:8000\n") == [
        "x: ControlPort 8000 non è su 127.0.0.1 (indirizzo 0.0.0.0)"]


def test_ascolti_non_desiderati():
    elenco = rl.ascolti(PROC_TCP) + rl.ascolti(PROC_TCP6)
    assert ("127.0.0.1", 5100) in elenco and ("0.0.0.0", 7100) in elenco
    assert ("127.0.0.1", 8080) not in elenco                     # connessione stabilita, non ascolto
    assert ("::", 7101) in elenco and ("::1", 8000) in elenco
    assert rl.problemi_ascolti(elenco) == ["porta 7100 in ascolto su 0.0.0.0", "porta 7101 in ascolto su ::"]


def test_patch_di_chutney_e_dockerfile():
    patch = (LAB / "chutney-dirport-loopback.patch").read_text()
    tolte = [r for r in patch.splitlines() if r.startswith("-") and not r.startswith("---")]
    aggiunte = [r for r in patch.splitlines() if r.startswith("+") and not r.startswith("+++")]
    assert tolte == ["-            DirPort {n.dirport.unwrap_or(0)}"]
    assert aggiunte == ["+            DirPort {addr_and_port_str(ip, n.dirport.unwrap()) if n.dirport.is_some() else 0}"]
    docker = (LAB / "Dockerfile").read_text()
    controllo = docker.index('test "$(git -C /opt/chutney rev-parse HEAD)"')
    applica = docker.index("git -C /opt/chutney apply --verbose /tmp/chutney-dirport-loopback.patch")
    installa = docker.index("pip install --no-cache-dir /opt/chutney")
    assert controllo < applica < installa


def test_file_della_rete_invariati_rispetto_al_libro():
    """Il listato del cap. 19 resta identico al file: la correzione non tocca la rete."""
    libro = (LAB.parents[2] / "source" / "it" / "capitoli" / "19-rete-privata.tex").read_text()
    rete = (LAB / "chutney" / "networks" / "libro").read_text()
    listato = libro[libro.index('Authority = Node(tag="a"'):libro.index("ConfigureNodes(NODES)")]
    codice = [r for r in rete.splitlines() if r.strip() and not r.startswith("#")]
    assert [r for r in listato.splitlines() if r.strip()] == codice[:len([r for r in listato.splitlines() if r.strip()])]
    assert codice[-1] == "ConfigureNodes(NODES)"


def test_arti_config_legge_dirport_con_e_senza_indirizzo(tmp_path, monkeypatch):
    """Regressione: con «DirPort 127.0.0.1:7100» arti_config.py non trovava più la porta."""
    import importlib
    import sys
    sys.path.insert(0, str(LAB))
    ac = importlib.import_module("arti_config")
    for i, riga in enumerate(("DirPort 7100", "DirPort 127.0.0.1:7101", "DirPort 127.0.0.1:7102")):
        d = tmp_path / f"00{i}a"
        (d / "keys").mkdir(parents=True)
        (d / "fingerprint").write_text(f"test00{i}a {'A' * 40}\n")
        (d / "fingerprint-ed25519").write_text(f"test00{i}a {'B' * 43}\n")
        (d / "keys" / "authority_certificate").write_text(f"fingerprint {'C' * 40}\n")
        (d / "torrc").write_text(f"OrPort 127.0.0.1:510{i}\n{riga}\n")
    monkeypatch.setattr(ac, "NODI", tmp_path)
    assert [(o, p) for *_, o, p in ac.autorita()] == [("5100", "7100"), ("5101", "7101"), ("5102", "7102")]
