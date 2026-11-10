# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 6 — scaricare e verificare il consenso.

Riferimenti: dir-spec, "Vote and consensus status document formats",
"Signing documents", "General-use HTTP URLs", "Creating key certificates".
Modulo didattico: solo per la rete privata del libro.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .celle import ComandoRelay, MessaggioRelay
from .circuito import Circuito, ErroreCircuito
from .stream import Stream


# --- Scaricare documenti con BEGIN_DIR ------------------------------------------

def scarica(circ: Circuito, percorso: str, stream_id: int) -> bytes:
    """GET HTTP/1.0 sul servizio di directory dell'ultimo salto, via BEGIN_DIR."""
    if any(ch in percorso for ch in ("\r", "\n", "\x00")):
        raise ErroreCircuito("percorso HTTP con caratteri di controllo")
    s = Stream(circ, stream_id)
    circ.invia(MessaggioRelay(ComandoRelay.BEGIN_DIR, stream_id, b""))
    _, msg = s._prossimo()
    if msg.comando != ComandoRelay.CONNECTED:
        raise ErroreCircuito(f"BEGIN_DIR rifiutato: {msg.comando}")
    s.aperto = True
    s.invia(f"GET {percorso} HTTP/1.0\r\n\r\n".encode())
    risposta = s.ricevi_tutto()
    intestazione, separator, corpo = risposta.partition(b"\r\n\r\n")
    if not separator:
        raise ErroreCircuito("risposta HTTP senza separatore intestazione-corpo")
    stato = intestazione.split(b"\r\n")[0]
    if not re.fullmatch(rb"HTTP/1\.[01] 200(?:[ \t].*)?", stato):
        raise ErroreCircuito(f"{percorso}: {stato.decode('utf-8', errors='replace')}")
    return corpo


# --- Documenti di rete: righe (item) e oggetti ------------------------------------

@dataclass
class Item:
    parola: str
    argomenti: list[str]
    oggetto: bytes | None = None      # contenuto di un blocco -----BEGIN ...-----


def items(testo: str) -> list[Item]:
    """Divide un documento nel formato "netdoc" in item (dir-spec, netdoc)."""
    uscita, righe, i = [], testo.split("\n"), 0
    while i < len(righe):
        riga = righe[i]
        i += 1
        if not riga:
            continue
        parola, *argomenti = riga.split(" ")
        oggetto = None
        if i < len(righe) and righe[i].startswith("-----BEGIN "):
            label = righe[i][len("-----BEGIN "):-5]
            expected_end = f"-----END {label}-----"
            j = i + 1
            while j < len(righe) and righe[j] != expected_end:
                if righe[j].startswith("-----END "):
                    raise ValueError("blocco PEM senza chiusura o non corrispondente")
                j += 1
            if j == len(righe):
                raise ValueError("blocco PEM senza chiusura o non corrispondente")
            oggetto = "\n".join(righe[i:j + 1]).encode()
            i = j + 1
        uscita.append(Item(parola, argomenti, oggetto))
    return uscita


def _pem_corpo(oggetto: bytes) -> bytes:
    if not oggetto or len(oggetto.split(b"\n")) < 3:
        raise ValueError("blocco PEM mancante o non valido")
    return base64.b64decode(b"".join(oggetto.split(b"\n")[1:-1]), validate=True)


def _b64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


# --- Il consenso -----------------------------------------------------------------

@dataclass
class VoceRelay:
    nome: str
    id_rsa: bytes
    ip: str
    orport: int
    flag: set[str] = field(default_factory=set)
    banda: int | None = None
    policy: str = ""
    microdesc: bytes | None = None
    versione: str = ""
    protocolli: str = ""


@dataclass
class Firma:
    algoritmo: str
    identita: str          # impronta dell'identità dell'autorità (hex)
    chiave_firma: str      # impronta della chiave di firma (hex)
    firma: bytes


@dataclass
class Consenso:
    testo: str
    intestazione: dict[str, list[str]]
    relay: list[VoceRelay]
    firme: list[Firma]
    parametri: dict[str, int]
    pesi: dict[str, int]


def analizza_consenso(testo: str) -> Consenso:
    intestazione, relay, firme = {}, [], []
    parametri, pesi = {}, {}
    corrente = None
    for it in items(testo):
        if it.parola == "r":
            corrente = VoceRelay(it.argomenti[0], _b64(it.argomenti[1]), it.argomenti[-3],
                                 int(it.argomenti[-2]))
            relay.append(corrente)
        elif it.parola == "s" and corrente:
            corrente.flag = set(it.argomenti)
        elif it.parola == "w" and corrente:
            campi = dict(a.split("=") for a in it.argomenti)
            corrente.banda = int(campi.get("Bandwidth", 0))
        elif it.parola == "p" and corrente:
            corrente.policy = " ".join(it.argomenti)
        elif it.parola == "m" and corrente:
            corrente.microdesc = _b64(it.argomenti[0])
        elif it.parola == "v" and corrente:
            corrente.versione = " ".join(it.argomenti)
        elif it.parola == "pr" and corrente:
            corrente.protocolli = " ".join(it.argomenti)
        elif it.parola == "params":
            parametri = {k: int(v) for k, v in (a.split("=") for a in it.argomenti)}
        elif it.parola == "bandwidth-weights":
            pesi = {k: int(v) for k, v in (a.split("=") for a in it.argomenti)}
        elif it.parola == "directory-signature":
            alg = it.argomenti[0] if len(it.argomenti) == 3 else "sha1"
            firme.append(Firma(alg, it.argomenti[-2], it.argomenti[-1], _pem_corpo(it.oggetto)))
        elif corrente is None:
            intestazione[it.parola] = it.argomenti
    return Consenso(testo, intestazione, relay, firme, parametri, pesi)


# --- Certificati delle autorità e verifica delle firme -------------------------------

@dataclass
class CertificatoAutorita:
    impronta_identita: str       # hex, maiuscolo
    chiave_firma: rsa.RSAPublicKey
    impronta_chiave_firma: str


def analizza_certificati(testo: str) -> list[CertificatoAutorita]:
    certificati, attuale = [], {}
    for it in items(testo):
        if it.parola == "fingerprint":
            attuale["id"] = it.argomenti[0].upper()
        elif it.parola == "dir-signing-key":
            der = _pem_corpo(it.oggetto)
            attuale["chiave"] = _carica_rsa_pkcs1(it.oggetto)
            attuale["impronta_chiave"] = hashlib.sha1(der).hexdigest().upper()
        elif it.parola == "dir-key-certification" and attuale:
            certificati.append(CertificatoAutorita(attuale["id"], attuale["chiave"],
                                                   attuale["impronta_chiave"]))
            attuale = {}
    return certificati


def _carica_rsa_pkcs1(oggetto: bytes) -> rsa.RSAPublicKey:
    # "-----BEGIN RSA PUBLIC KEY-----" è il formato PKCS#1, che cryptography legge come PEM.
    return load_pem_public_key(oggetto)


def testo_firmato(testo: str) -> bytes:
    """Parte del consenso coperta dalle firme: da "network-status-version" fino allo
    spazio dopo "directory-signature" (dir-spec, "directory-signature").

    I file scaricati da CollecTor iniziano con una riga di annotazione "@type ...",
    che non fa parte del documento firmato e va scartata.
    """
    inizio = re.search(r"(?m)^network-status-version ", testo)
    if inizio is None:
        raise ValueError("network-status-version missing")
    fine = re.search(r"(?m)^directory-signature ", testo[inizio.start():])
    if fine is None:
        raise ValueError("directory-signature missing")
    return testo[inizio.start():inizio.start() + fine.end()].encode()


def verifica_firma(consenso: Consenso, firma: Firma, cert: CertificatoAutorita) -> bool:
    """La firma è RSA PKCS#1 v1.5 del digest *senza* l'identificativo dell'algoritmo:
    ricaviamo il digest dalla firma e lo confrontiamo con quello calcolato."""
    if firma.algoritmo not in ("sha1", "sha256"):
        return False
    h = hashlib.sha256 if firma.algoritmo == "sha256" else hashlib.sha1
    atteso = h(testo_firmato(consenso.testo)).digest()
    try:
        ricavato = cert.chiave_firma.recover_data_from_signature(
            firma.firma, padding.PKCS1v15(), None)
    except Exception:
        return False
    return ricavato == atteso


def verifica_consenso(consenso: Consenso, certificati: list[CertificatoAutorita],
                      n_autorita: int) -> tuple[int, int, list[str]]:
    """Conta le autorità con almeno una firma valida. Restituisce (valide, richieste, dettagli).
    Attenzione: questa funzione conta firme matematicamente valide, ma non verifica l'autenticità, la scadenza o l'appartenenza a un insieme fidato dei certificati delle autorità."""
    per_chiave = {c.impronta_chiave_firma: c for c in certificati}
    valide, dettagli = set(), []
    for f in consenso.firme:
        cert = per_chiave.get(f.chiave_firma.upper())
        esito = bool(cert and cert.impronta_identita == f.identita.upper()
                     and verifica_firma(consenso, f, cert))
        dettagli.append(f"{f.identita[:8]} {f.algoritmo}: {'valida' if esito else 'NON valida'}")
        if esito:
            valide.add(f.identita.upper())
    return len(valide), n_autorita // 2 + 1, dettagli


# --- Microdescrittori ---------------------------------------------------------------

def analizza_microdescrittori(testo: str) -> dict[bytes, dict]:
    """Restituisce {sha256 del microdescrittore: campi}. Ogni microdescrittore inizia con onion-key."""
    risultato = {}
    for m in re.finditer(r"(?m)^onion-key\n.*?(?=^onion-key\n|^@last-listed |\Z)", testo, re.S):
        blocco = m.group().rstrip("\n") + "\n"
        campi = {}
        for it in items(blocco):
            if it.parola in ("ntor-onion-key",):
                campi["ntor"] = _b64(it.argomenti[0])
            elif it.parola == "id" and it.argomenti[0] == "ed25519":
                campi["ed25519"] = _b64(it.argomenti[1])
            elif it.parola == "family":
                campi["famiglia"] = it.argomenti
            elif it.parola == "p":
                campi["policy"] = " ".join(it.argomenti)
        risultato[hashlib.sha256(blocco.encode()).digest()] = campi
    return risultato
