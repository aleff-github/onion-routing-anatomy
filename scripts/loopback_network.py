#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Rete privata `libro`: porte solo su 127.0.0.1 e DNS degli exit solo locale.

  controlla        legge i torrc di labs/it/laboratorio/net e gli ascolti TCP reali del container
                   (/proc/net/tcp e tcp6): esce con 1 se un DirPort, ORPort, SocksPort o
                   ControlPort non è su 127.0.0.1, se un exit non usa dns_locale.conf o se
                   una porta del laboratorio è in ascolto fuori dal loopback.
  migra [--applica]
                   porta i torrc di una rete creata prima della patch di Chutney a quello che
                   Chutney genera oggi: «DirPort N» -> «DirPort 127.0.0.1:N» e, sugli exit,
                   ServerDNSResolvConfFile -> /lab/dns_locale.conf. Nessun'altra riga cambia,
                   chiavi e identità non vengono toccate. Senza --applica mostra soltanto.
                   Va eseguito a rete ferma.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
LAB = RADICE / "labs" / "it" / "laboratorio"
CONTAINER = "torlibro-rete"
DNS_CONF = "/lab/dns_locale.conf"
OPZIONI_PORTA = ("DirPort", "OrPort", "ORPort", "SocksPort", "ControlPort")
# Porte del laboratorio (docs/it/procedura-laboratori-dal-vivo.md, §2) e resolver locale.
PORTE_LAB = (set(range(5100, 5112)) | set(range(7100, 7112)) | set(range(8000, 8012))
             | set(range(9000, 9012)) | {5300, 8080, 8081, 8095, 9150, 9909})


def migra(testo: str) -> str:
    """Le sole due modifiche della patch; il resto del torrc resta identico byte per byte."""
    # «DirPort 0» (nessun DirPort, come sui bridge) resta com'è.
    testo = re.sub(r"^DirPort ([1-9]\d*)$", r"DirPort 127.0.0.1:\1", testo, flags=re.M)
    return re.sub(r"^ServerDNSResolvConfFile .*$", f"ServerDNSResolvConfFile {DNS_CONF}", testo, flags=re.M)


def porte_torrc(testo: str) -> list[tuple[str, str | None, int]]:
    """(opzione, indirizzo o None, porta) per le opzioni di ascolto attive (porta != 0)."""
    porte = []
    for m in re.finditer(r"^(%s) (\S+)" % "|".join(OPZIONI_PORTA), testo, re.M):
        valore = m.group(2)
        indirizzo, _, porta = valore.rpartition(":")
        if not porta.isdigit() or int(porta) == 0:
            continue
        porte.append((m.group(1), indirizzo.strip("[]") or None, int(porta)))
    return porte


def problemi_torrc(nome: str, testo: str) -> list[str]:
    problemi = [f"{nome}: {opz} {porta} non è su 127.0.0.1 (indirizzo {ind or 'tutte le interfacce'})"
                for opz, ind, porta in porte_torrc(testo) if ind != "127.0.0.1"]
    if re.search(r"^ExitRelay 1$", testo, re.M):
        dns = re.search(r"^ServerDNSResolvConfFile (.*)$", testo, re.M)
        if not dns or dns.group(1) != DNS_CONF:
            problemi.append(f"{nome}: exit senza ServerDNSResolvConfFile {DNS_CONF}")
    return problemi


def ascolti(proc_net: str) -> list[tuple[str, int]]:
    """Socket TCP in ascolto (stato 0A) da /proc/net/tcp o tcp6."""
    risultato = []
    for riga in proc_net.splitlines()[1:]:
        campi = riga.split()
        if len(campi) < 4 or campi[3] != "0A":
            continue
        ind_hex, porta_hex = campi[1].split(":")
        grezzo = bytes.fromhex(ind_hex)
        if len(grezzo) == 4:
            ind = str(ipaddress.IPv4Address(grezzo[::-1]))
        else:   # tcp6: quattro parole a 32 bit in ordine dell'host (little endian)
            ind = str(ipaddress.IPv6Address(b"".join(grezzo[i:i + 4][::-1] for i in range(0, 16, 4))))
        risultato.append((ind, int(porta_hex, 16)))
    return risultato


def problemi_ascolti(elenco: list[tuple[str, int]]) -> list[str]:
    return [f"porta {porta} in ascolto su {ind}" for ind, porta in elenco
            if porta in PORTE_LAB and not ipaddress.ip_address(ind).is_loopback]


def ascolti_ss(testo: str) -> list[tuple[str, int, str]]:
    """(indirizzo, porta, processo) dalle righe di «ss -ltnpH» (socket TCP in ascolto)."""
    risultato = []
    for riga in testo.splitlines():
        campi = riga.split()
        if len(campi) < 4 or campi[0] != "LISTEN":
            continue
        locale = campi[3]
        indirizzo, _, porta = locale.rpartition(":")
        indirizzo = indirizzo.strip("[]").split("%")[0]
        indirizzo = {"*": "0.0.0.0", "": "0.0.0.0"}.get(indirizzo, indirizzo)
        m = re.search(r'users:\(\("([^"]+)"', riga)
        risultato.append((indirizzo, int(porta), m.group(1) if m else "?"))
    return risultato


def problemi_ascolti_processi(elenco: list[tuple[str, int, str]],
                              processi: tuple[str, ...] = ("tor", "obfs4proxy")) -> list[str]:
    """Ogni ascolto TCP di tor o obfs4proxy fuori dal loopback, qualunque sia la porta."""
    problemi = []
    for ind, porta, proc in elenco:
        if proc not in processi:
            continue
        try:
            loopback = ipaddress.ip_address(ind).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            problemi.append(f"{proc} in ascolto su {ind}:{porta}")
    return problemi


def _torrc() -> list[Path]:
    return sorted((LAB / "net" / "nodes").glob("*/torrc"))


def controlla() -> int:
    problemi = []
    for t in _torrc():
        problemi += problemi_torrc(t.parent.name, t.read_text())
    proc = ""
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        r = subprocess.run(["docker", "exec", CONTAINER, "cat", f], capture_output=True, text=True)
        if r.returncode == 0:
            proc += r.stdout if not proc else "\n".join(r.stdout.splitlines()[1:]) + "\n"
        elif f.endswith("tcp"):
            print(f"[NO!] impossibile leggere {f} nel container: {r.stderr.strip()}")
            return 1
    elenco = ascolti(proc)
    problemi += problemi_ascolti(elenco)
    lab = sorted({(i, p) for i, p in elenco if p in PORTE_LAB}, key=lambda x: x[1])
    print(f"torrc controllati: {len(_torrc())}; porte del laboratorio in ascolto: "
          + ", ".join(f"{i}:{p}" for i, p in lab))
    for p in problemi:
        print(f"[NO!] {p}")
    print("[OK ] tutto su 127.0.0.1" if not problemi else f"{len(problemi)} problemi")
    return 1 if problemi else 0


def migra_rete(applica: bool) -> int:
    if (LAB / "verifica-bridge.stato").exists() or (LAB / "net-libro").exists():
        print("scambio di verifica-lab-bridge interrotto: ripristinalo prima (procedura, §8)")
        return 2
    cambiati = 0
    for t in _torrc():
        prima = t.read_text()
        dopo = migra(prima)
        if dopo == prima:
            continue
        cambiati += 1
        for a, b in zip(prima.splitlines(), dopo.splitlines()):
            if a != b:
                print(f"{t.parent.name}: {a}  ->  {b}")
        if applica:
            tmp = t.with_name("torrc.migrazione")
            tmp.write_text(dopo)
            os.replace(tmp, t)
    print(f"{cambiati} torrc da aggiornare" + (" (aggiornati)" if applica else " (nessuna modifica: --applica)"))
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["controlla"]:
        return controlla()
    if argv[:1] == ["migra"]:
        return migra_rete("--applica" in argv[1:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
