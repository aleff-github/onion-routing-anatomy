#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controlla l'intera cronologia, non solo i file attuali: ogni blob di ogni commit
raggiungibile e ogni messaggio di commit.

Cerca dati che non devono essere pubblicati: indirizzi email personali (sono ammessi solo
domini di esempio, di test, del Tor Project e gli indirizzi noreply), riferimenti a sessioni
di lavoro, chiavi private, chiavi e identita' di nodi Tor, token, catture di traffico, file
con nomi sospetti. Da eseguire prima di ogni push che riscrive o pubblica la cronologia.

    python3 scripts/check_history.py [riferimento...]     (predefinito: --all)
"""
import re
import subprocess
import sys

DOMINI_AMMESSI = ("example.org", "example.com", "example.net", "example.invalid", "test.test",
                  "torproject.org", "noreply.github.com", "noreply@anthropic.com")
# Solo questa identità tecnica non personale è approvata per i commit automatici.
INDIRIZZI_AUTOMATICI_AMMESSI = {"ai-assistant@onion-routing-anatomy.invalid"}
EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CONTENUTI = {
    # Alcuni modelli sono spezzati in due letterali, perche' questo file non trovi se stesso.
    "riferimento a una sessione di lavoro": rb"claude\.ai/code|Claude-Sess" rb"ion:|session_0[0-9A-Za-z]{10,}",
    "percorso dell'ambiente di lavoro": rb"/tmp/clau" rb"de-|/root/\.ccr",
    "chiave privata PEM": rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "chiave di un nodo Tor": rb"== ed25519v1-sec" rb"ret|ED25519-V3:[A-Za-z0-9+/]{40}",
    "token": rb"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}",
    "cattura di traffico": rb"\A(\xd4\xc3\xb2\xa1|\xa1\xb2\xc3\xd4|\x0a\x0d\x0d\x0a)",
}
NOMI = re.compile(r"(^|/)(secret_id_key|ed25519_master_id_secret_key|ed25519_signing_secret_key|"
                  r"hs_ed25519_secret_key|authority_signing_key|authority_identity_key|\.env|"
                  r"id_rsa|id_ed25519)$|\.(pcap|pcapng|pem|p12|kdbx)$")


def git(*argomenti):
    return subprocess.run(["git", *argomenti], check=True, capture_output=True).stdout


def email_vietate(dati):
    return sorted({m.decode(errors="replace") for m in EMAIL.findall(dati)
                   if m.decode(errors="replace").lower() not in INDIRIZZI_AUTOMATICI_AMMESSI
                   and not m.decode(errors="replace").lower().endswith(DOMINI_AMMESSI)})


def main():
    riferimenti = sys.argv[1:] or ["--all"]
    commit = git("rev-list", *riferimenti).decode().split()
    problemi = []
    for c in commit:
        messaggio = git("log", "-1", "--format=%an <%ae>%n%cn <%ce>%n%B", c)
        for nome, modello in CONTENUTI.items():
            if re.search(modello, messaggio):
                problemi.append(f"commit {c[:10]}: {nome} nel messaggio")
        for e in email_vietate(messaggio):
            problemi.append(f"commit {c[:10]}: email {e} nel messaggio o nell'autore")
    percorsi = {}
    for riga in git("rev-list", "--objects", *riferimenti).decode().splitlines():
        parti = riga.split(" ", 1)
        if len(parti) == 2:
            percorsi.setdefault(parti[0], set()).add(parti[1])
    blob = []
    elenco = "\n".join(percorsi).encode()
    for riga in subprocess.run(["git", "cat-file", "--batch-check=%(objectname) %(objecttype)"],
                               input=elenco, capture_output=True, check=True).stdout.splitlines():
        sha, tipo = riga.decode().split()
        if tipo == "blob":
            blob.append(sha)
    for sha in blob:
        nomi = sorted(percorsi[sha])
        for p in nomi:
            if NOMI.search(p):
                problemi.append(f"{p}: nome di file sospetto")
        dati = git("cat-file", "blob", sha)
        for nome, modello in CONTENUTI.items():
            if re.search(modello, dati):
                problemi.append(f"{nomi[0]} (blob {sha[:10]}): {nome}")
        for e in email_vietate(dati):
            problemi.append(f"{nomi[0]} (blob {sha[:10]}): email {e}")
    for p in sorted(set(problemi)):
        print(p)
    print(f"Cronologia: {len(commit)} commit, {len(blob)} blob, {len(set(problemi))} problemi")
    return 1 if problemi else 0


if __name__ == "__main__":
    sys.exit(main())
