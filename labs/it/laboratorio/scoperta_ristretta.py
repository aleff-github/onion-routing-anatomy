# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio 13 (capitolo 21): un onion service con scoperta ristretta.
# Crea su 009h un servizio con un client autorizzato, lo interroga senza e con la chiave,
# e ripristina la configurazione di partenza. Eseguibile più volte.
import base64
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

LAB = Path(__file__).resolve().parent
NODI = LAB / "net" / "nodes"
SERVIZIO, CLIENT = NODI / "009h", NODI / "008c"
HS, AUTH = SERVIZIO / "hs_ristretto", CLIENT / "onion_auth"
CONTAINER, SOCKS = "torlibro-rete", "127.0.0.1:9008"
b32 = lambda b: base64.b32encode(b).decode().rstrip("=")
MARCATORE = ".laboratorio13-creato-dallo-script"


def _rimuovi_solo_directory_del_laboratorio(cartella: Path) -> None:
    """Non cancellare chiavi non create da questo laboratorio, nemmeno al primo avvio."""
    if not cartella.exists():
        return
    if not (cartella / MARCATORE).is_file():
        raise RuntimeError(f"Directory preesistente non riconosciuta: {cartella}; backup e verifica manuale necessari")
    shutil.rmtree(cartella)


def _scrivi_segreto_privato(percorso: Path, valore: str) -> None:
    """Crea il file della chiave con permessi 0600, senza seguire un file preesistente."""
    fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(valore)


def hup(nodo: Path):
    """Segnale HUP al tor del nodo, individuato dalla riga di comando: dopo un riavvio
    manuale il file pid può non essere aggiornato."""
    subprocess.run(["docker", "exec", CONTAINER, "pkill", "-HUP", "-f", f"{nodo.name}/torrc"], check=True)


def curl(indirizzo: str) -> str:
    r = subprocess.run(["docker", "exec", CONTAINER, "curl", "-s", "-o", "/dev/null",
                        "-w", "%{http_code}", "-m", "60", "--socks5-hostname", SOCKS,
                        f"http://{indirizzo}/"], capture_output=True, text=True)
    return r.stdout.strip() or "errore SOCKS"


def interno(nodo: Path) -> str:
    """Percorso della cartella del nodo come lo vede tor dentro il container."""
    return re.search(r"^DataDirectory (\S+)", (nodo / "torrc").read_text(), re.M).group(1)


def aggiungi(torrc: Path, righe: str) -> str:
    originale = torrc.read_text()
    torrc.write_text(originale + righe)
    return originale


def ripulisci():
    """Toglie soltanto residui riconoscibili di una esecuzione precedente interrotta.
    Una cartella authorized_clients vuota NON protegge il servizio: zero chiavi valide
    disabilitano l'autorizzazione nel codice C di tor 0.4.9.13.
    """
    # Fallire prima di toccare i torrc quando sono presenti dati non nostri.
    for cartella in (HS, AUTH):
        if cartella.exists() and not (cartella / MARCATORE).is_file():
            raise RuntimeError(f"Directory preesistente non riconosciuta: {cartella}")
    for nodo, chiave in ((SERVIZIO, "hs_ristretto"), (CLIENT, "ClientOnionAuthDir")):
        torrc = nodo / "torrc"
        righe, out, salta = torrc.read_text().splitlines(), [], False
        for r in righe:
            if chiave in r and r.startswith(("HiddenServiceDir", "ClientOnionAuthDir")):
                salta = r.startswith("HiddenServiceDir")
                continue
            if salta and r.startswith("HiddenServicePort"):
                salta = False
                continue
            out.append(r)
        if out != righe:                    # nessun residuo: il torrc resta identico
            torrc.write_text("\n".join(out).rstrip() + "\n")
    _rimuovi_solo_directory_del_laboratorio(HS)
    _rimuovi_solo_directory_del_laboratorio(AUTH)


def main():
    ripulisci()
    sk = X25519PrivateKey.generate()
    priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    (HS / "authorized_clients").mkdir(parents=True)
    HS.chmod(0o700)
    (HS / MARCATORE).touch()
    (HS / "authorized_clients" / "alice.auth").write_text(f"descriptor:x25519:{b32(pub)}\n")
    orig_s = aggiungi(SERVIZIO / "torrc",
                      f"\nHiddenServiceDir {interno(SERVIZIO)}/hs_ristretto\n"
                      "HiddenServicePort 80 127.0.0.1:8080\n")
    AUTH.mkdir(mode=0o700)
    (AUTH / MARCATORE).touch()
    orig_c = aggiungi(CLIENT / "torrc", f"\nClientOnionAuthDir {interno(CLIENT)}/onion_auth\n")
    try:
        hup(SERVIZIO)
        for _ in range(30):
            if (HS / "hostname").exists():
                break
            time.sleep(1)
        indirizzo = (HS / "hostname").read_text().strip()
        hup(CLIENT)
        time.sleep(20)                      # attesa della pubblicazione dei descrittori
        print(f"servizio ristretto: {indirizzo}")
        print(f"senza chiave: {curl(indirizzo)}")
        _scrivi_segreto_privato(AUTH / "alice.auth_private",
            f"{indirizzo.removesuffix('.onion')}:descriptor:x25519:{b32(priv)}\n")
        hup(CLIENT)
        time.sleep(3)
        print(f"con la chiave: {curl(indirizzo)}")
    finally:
        (SERVIZIO / "torrc").write_text(orig_s)
        (CLIENT / "torrc").write_text(orig_c)
        _rimuovi_solo_directory_del_laboratorio(AUTH)
        _rimuovi_solo_directory_del_laboratorio(HS)
        hup(SERVIZIO)
        hup(CLIENT)


if __name__ == "__main__":
    main()
