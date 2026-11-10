# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 1 — aprire un canale verso un relay e verificarne l'identità.

Riferimenti: tor-spec, "Channels" e "Negotiating and initializing channels";
cert-spec, "Tor Ed25519 Certificates". Il client non si autentica (come ogni client
Tor): invia solo VERSIONS e NETINFO.
Modulo didattico: da usare solo sulla rete privata del libro (laboratorio/).
"""
from __future__ import annotations

import base64
import hashlib
import os
import ipaddress
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .celle import Cella, Comando, ErroreCella, cella_versions, codifica, decodifica, negozia_versione

VERSIONI_SUPPORTATE = [4, 5]      # come Arti: niente link protocol 3

# Tipi di certificato nella cella CERTS (cert-spec, "Certificate types").
CERT_RSA_ID_X509 = 0x02
CERT_IDENTITY_V_SIGNING = 0x04
CERT_SIGNING_V_TLS_CERT = 0x05
CERT_RSA_ID_V_IDENTITY = 0x07
EXT_SIGNED_WITH_ED25519_KEY = 0x04


class ErroreCanale(Exception):
    """L'handshake di canale non è andato a buon fine."""


# --- Certificati Ed25519 di Tor ------------------------------------------------

@dataclass
class CertificatoEd:
    tipo: int
    scadenza_ore: int            # ore dall'epoca Unix
    tipo_chiave: int
    chiave_certificata: bytes    # 32 byte
    estensioni: dict[int, tuple[int, bytes]]   # tipo -> (flag, dati)
    firmato: bytes               # byte coperti dalla firma
    firma: bytes

    @property
    def chiave_firmataria(self) -> bytes | None:
        """Chiave inclusa nell'estensione signed-with-ed25519-key, se presente."""
        est = self.estensioni.get(EXT_SIGNED_WITH_ED25519_KEY)
        return est[1] if est else None

    def scaduto(self, adesso: float | None = None) -> bool:
        adesso = time.time() if adesso is None else adesso
        return self.scadenza_ore * 3600 < adesso

    def verifica_firma(self, chiave_pubblica: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(chiave_pubblica).verify(self.firma, self.firmato)
        except InvalidSignature:
            raise ErroreCanale(f"firma non valida sul certificato di tipo {self.tipo}") from None


def decodifica_cert_ed(dati: bytes) -> CertificatoEd:
    """Interpreta un certificato Ed25519 di Tor (cert-spec, ed-certs)."""
    if len(dati) < 40 + 64 or dati[0] != 1:
        raise ErroreCanale("certificato Ed25519 malformato o di versione sconosciuta")
    _, tipo, scadenza, tipo_chiave = struct.unpack(">BBIB", dati[:7])
    chiave = dati[7:39]
    n_est = dati[39]
    pos, estensioni = 40, {}
    for _ in range(n_est):
        if pos + 4 > len(dati) - 64:
            raise ErroreCanale("intestazione di estensione Ed25519 incompleta")
        lung, tipo_est, flag = struct.unpack(">HBB", dati[pos:pos + 4])
        if pos + 4 + lung > len(dati) - 64:
            raise ErroreCanale("estensione oltre la fine del certificato")
        corpo = dati[pos + 4:pos + 4 + lung]
        if len(corpo) != lung:
            raise ErroreCanale("estensione oltre la fine del certificato")
        if tipo_est != EXT_SIGNED_WITH_ED25519_KEY and flag & 1:
            # AFFECTS_VALIDATION su un'estensione che non conosciamo: rifiutare.
            raise ErroreCanale(f"estensione sconosciuta {tipo_est} che influisce sulla validità")
        if tipo_est in estensioni:
            raise ErroreCanale("estensione Ed25519 duplicata")
        if tipo_est == EXT_SIGNED_WITH_ED25519_KEY and lung != 32:
            raise ErroreCanale("lunghezza errata dell'estensione della chiave Ed25519")
        estensioni[tipo_est] = (flag, corpo)
        pos += 4 + lung
    if len(dati) != pos + 64:
        raise ErroreCanale("lunghezza del certificato incoerente")
    return CertificatoEd(tipo, scadenza, tipo_chiave, chiave, estensioni, dati[:pos], dati[pos:])


def decodifica_certs(corpo: bytes) -> dict[int, bytes]:
    """Corpo di una cella CERTS -> {CertType: certificato grezzo}."""
    if not corpo:
        raise ErroreCanale("cella CERTS vuota")
    n, pos, certificati = corpo[0], 1, {}
    for _ in range(n):
        if pos + 3 > len(corpo):
            raise ErroreCanale("intestazione CERTS incompleta")
        tipo, lung = struct.unpack(">BH", corpo[pos:pos + 3])
        if pos + 3 + lung > len(corpo):
            raise ErroreCanale("certificato CERTS oltre il corpo della cella")
        if tipo in certificati:
            raise ErroreCanale(f"più di un certificato di tipo {tipo}")
        certificati[tipo] = corpo[pos + 3:pos + 3 + lung]
        pos += 3 + lung
    return certificati


def verifica_identita_responder(certificati: dict[int, bytes], cert_tls_der: bytes) -> bytes:
    """Applica le regole di "Authenticating the responder from its CERTS".

    Restituisce KP_relayid_ed (32 byte) se la catena
        identità Ed25519 -> chiave di firma -> certificato TLS
    è valida, altrimenti solleva ErroreCanale.
    """
    try:
        id_v_sign = decodifica_cert_ed(certificati[CERT_IDENTITY_V_SIGNING])
        sign_v_tls = decodifica_cert_ed(certificati[CERT_SIGNING_V_TLS_CERT])
    except KeyError as e:
        raise ErroreCanale(f"manca il certificato di tipo {e.args[0]}") from None

    if id_v_sign.tipo != CERT_IDENTITY_V_SIGNING or sign_v_tls.tipo != CERT_SIGNING_V_TLS_CERT:
        raise ErroreCanale("tipo del certificato Ed25519 non coerente con CERTS")
    # Compatibilità: nei vecchi certificati di tipo 5 il tipo chiave era 01 anziché 03.
    if id_v_sign.tipo_chiave != 1 or sign_v_tls.tipo_chiave not in (1, 3):
        raise ErroreCanale("tipo di chiave non valido nel certificato del relay")
    if not cert_tls_der:
        raise ErroreCanale("certificato TLS del relay assente")
    identita = id_v_sign.chiave_firmataria
    if identita is None:
        raise ErroreCanale("IDENTITY_V_SIGNING senza chiave firmataria")
    id_v_sign.verifica_firma(identita)                      # auto-firmato dall'identità
    chiave_firma = id_v_sign.chiave_certificata             # KP_relaysign_ed
    sign_v_tls.verifica_firma(chiave_firma)
    if sign_v_tls.chiave_certificata != hashlib.sha256(cert_tls_der).digest():
        raise ErroreCanale("SIGNING_V_TLS_CERT non corrisponde al certificato TLS ricevuto")
    for c in (id_v_sign, sign_v_tls):
        if c.scaduto():
            raise ErroreCanale(f"certificato di tipo {c.tipo} scaduto")
    return identita


# --- NETINFO ------------------------------------------------------------------

def codifica_indirizzo(ip: str) -> bytes:
    a = ipaddress.ip_address(ip)
    return bytes([4 if a.version == 4 else 6, len(a.packed)]) + a.packed


def decodifica_indirizzo(dati: bytes, pos: int) -> tuple[str | None, int]:
    if pos < 0 or pos + 2 > len(dati):
        raise ErroreCanale("indirizzo NETINFO incompleto")
    tipo, lung = dati[pos], dati[pos + 1]
    if pos + 2 + lung > len(dati):
        raise ErroreCanale("indirizzo NETINFO oltre il corpo del messaggio")
    valore = dati[pos + 2:pos + 2 + lung]
    ip = None
    if (tipo, lung) in ((4, 4), (6, 16)):
        ip = str(ipaddress.ip_address(valore))
    return ip, pos + 2 + lung


def cella_netinfo_client(ip_relay: str) -> Cella:
    """NETINFO di un client: orario a zero e nessun indirizzo proprio."""
    corpo = struct.pack(">I", 0) + codifica_indirizzo(ip_relay) + b"\x00"
    return Cella(0, Comando.NETINFO, corpo)


@dataclass
class Netinfo:
    orario: int
    tuo_indirizzo: str | None
    miei_indirizzi: list[str | None]


def decodifica_netinfo(corpo: bytes) -> Netinfo:
    if len(corpo) < 4:
        raise ErroreCanale("cella NETINFO incompleta")
    (orario,) = struct.unpack(">I", corpo[:4])
    tuo, pos = decodifica_indirizzo(corpo, 4)
    if pos >= len(corpo):
        raise ErroreCanale("cella NETINFO incompleta")
    n, pos = corpo[pos], pos + 1
    miei = []
    for _ in range(n):
        ip, pos = decodifica_indirizzo(corpo, pos)
        miei.append(ip)
    return Netinfo(orario, tuo, miei)


# --- Il canale ----------------------------------------------------------------

@dataclass
class Canale:
    sock: ssl.SSLSocket
    versione: int
    identita_ed: bytes
    netinfo: Netinfo
    metodi_auth: list[int]
    buffer: bytes = b""
    registro: list[str] = field(default_factory=list)

    def invia(self, cella: Cella) -> None:
        self.sock.sendall(codifica(cella, self.versione))

    def ricevi(self) -> Cella:
        while (r := decodifica(self.buffer, self.versione)) is None:
            dati = self.sock.recv(65536)
            if not dati:
                raise ErroreCanale("connessione chiusa dal relay")
            self.buffer += dati
        cella, self.buffer = r
        return cella


def _leggi(sock, buffer: bytes, versione: int) -> tuple[Cella, bytes]:
    while (r := decodifica(buffer, versione)) is None:
        dati = sock.recv(65536)
        if not dati:
            raise ErroreCanale("connessione chiusa durante l'handshake")
        buffer += dati
    return r


def apri_canale(host: str, porta: int, identita_attesa: bytes | None = None,
                timeout: float = 10.0, origine: str | None = None) -> Canale:
    """Apre un canale verso un relay, come farebbe un client (senza autenticarsi).
    `origine` sceglie l'indirizzo locale da cui partire (per esempio 127.0.0.2)."""
    # Senza identita_attesa, CERTS autentica solo l'identità dichiarata dal relay.
    # SSLKEYLOGFILE esporta segreti TLS: abilitarlo solo nella rete privata controllata.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Il certificato TLS di un relay è autofirmato e non ha un nome di dominio:
    # l'identità si verifica dopo, con la cella CERTS.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Convenzione dei browser: se SSLKEYLOGFILE è impostata, vi scriviamo le chiavi della
    # sessione TLS, così che Wireshark possa decifrare il *nostro* canale (capitolo 20).
    if os.environ.get("SSLKEYLOGFILE"):
        ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
    sorgente = (origine, 0) if origine else None
    sock_grezzo = socket.create_connection((host, porta), timeout=timeout,
                                           source_address=sorgente)
    try:
        sock = ctx.wrap_socket(sock_grezzo)
    except BaseException:
        sock_grezzo.close()
        raise
    try:
        cert_tls = sock.getpeercert(binary_form=True)
        if not cert_tls:
            raise ErroreCanale("certificato TLS del relay assente")
        registro = [f"TLS {sock.version()} {sock.cipher()[0]}"]
    
        sock.sendall(codifica(cella_versions(VERSIONI_SUPPORTATE), 0))
        buffer, versione = b"", 0
        certificati, metodi, netinfo = None, [], None
        while netinfo is None:
            cella, buffer = _leggi(sock, buffer, versione)
            if not versione and cella.comando != Comando.VERSIONS:
                raise ErroreCanale("la prima cella dell'handshake deve essere VERSIONS")
            registro.append(f"<- {(Comando._value2member_map_.get(cella.comando).name if cella.comando in Comando._value2member_map_ else cella.comando)} ({len(cella.corpo)} byte)")
            if cella.comando == Comando.VERSIONS:
                if versione:
                    continue                                  # VERSIONS successivi: ignorati
                versione = negozia_versione(VERSIONI_SUPPORTATE, cella.corpo)
            elif cella.comando == Comando.VPADDING:
                continue
            elif cella.comando == Comando.CERTS:
                if certificati is not None:
                    raise ErroreCanale("cella CERTS duplicata")
                certificati = decodifica_certs(cella.corpo)
            elif cella.comando == Comando.AUTH_CHALLENGE:
                if len(cella.corpo) < 34:
                    raise ErroreCanale("elenco dei metodi AUTH_CHALLENGE incompleto")
                (n,) = struct.unpack(">H", cella.corpo[32:34])
                if len(cella.corpo) < 34 + 2 * n:
                    raise ErroreCanale("elenco dei metodi AUTH_CHALLENGE incompleto")
                metodi = [m for (m,) in struct.iter_unpack(">H", cella.corpo[34:34 + 2 * n])]
            elif cella.comando == Comando.NETINFO:
                netinfo = decodifica_netinfo(cella.corpo)
            else:
                raise ErroreCanale(f"cella inattesa durante l'handshake: {cella.comando}")
    
        if not versione:
            raise ErroreCanale("negoziazione VERSIONS mancante")
        if certificati is None:
            raise ErroreCanale("NETINFO ricevuto prima di CERTS")
        identita = verifica_identita_responder(certificati, cert_tls)
        if identita_attesa is not None and identita != identita_attesa:
            raise ErroreCanale("il relay ha un'identità diversa da quella attesa")
    
        canale = Canale(sock, versione, identita, netinfo, metodi, buffer, registro)
        canale.invia(cella_netinfo_client(sock.getpeername()[0]))
        registro.append("-> NETINFO: canale aperto")
        return canale
    except BaseException:
        sock.close()
        raise


def identita_da_file(percorso: str) -> bytes:
    """Legge il file fingerprint-ed25519 di un nodo: '<nome> <chiave base64>'."""
    b64 = open(percorso).read().split()[1]
    return base64.b64decode(b64 + "=" * (-len(b64) % 4))
