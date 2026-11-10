# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 8 — onion service v3: indirizzi, chiavi accecate, HSDir, descrittori.

Riferimenti: rend-spec, "Encoding onion addresses", "Deriving blinded keys and
subcredentials", "Locating, uploading, and downloading hidden service descriptors",
"Hidden service descriptors: encryption format", Appendice A (key blinding).
Modulo didattico: solo per la rete privata del libro.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .canale import decodifica_cert_ed

# --- Indirizzi .onion -------------------------------------------------------------

VERSIONE = 3


def _require_bytes(value: bytes, size: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{label} deve contenere esattamente {size} byte")


def _require_u64(value: int, label: str, *, positive: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value < 2 ** 64):
        raise ValueError(f"{label} deve essere un uint64 non negativo")
    if positive and value == 0:
        raise ValueError(f"{label} deve essere positivo")




def indirizzo_onion(chiave: bytes) -> str:
    """Codifica un indirizzo onion v3 canonico da una chiave pubblica Ed25519 di 32 byte."""
    _require_bytes(chiave, 32, "chiave identità onion")
    checksum = hashlib.sha3_256(b".onion checksum" + chiave + bytes([VERSIONE])).digest()[:2]
    return base64.b32encode(chiave + checksum + bytes([VERSIONE])).decode("ascii").lower() + ".onion"

def chiave_da_indirizzo(indirizzo: str) -> bytes:
    """Verifica hostname, alfabeto Base32, versione e checksum."""
    if not isinstance(indirizzo, str):
        raise ValueError("indirizzo onion v3 non valido")
    canonical = indirizzo.lower()
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", canonical):
        raise ValueError("indirizzo onion v3 non valido")
    raw = base64.b32decode(canonical[:-6].upper(), casefold=False)
    chiave, checksum, version = raw[:32], raw[32:34], raw[34]
    if version != VERSIONE:
        raise ValueError("versione indirizzo onion v3 non supportata")
    expected = hashlib.sha3_256(b".onion checksum" + chiave + bytes([version])).digest()[:2]
    if not hmac.compare_digest(expected, checksum):
        raise ValueError("checksum indirizzo onion v3 non valido")
    return chiave

# --- Aritmetica di Ed25519 (RFC 8032), quanto basta per accecare le chiavi ----------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _x_da_y(y: int, segno: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * I % P
    if (x * x - xx) % P:
        raise ValueError("punto non valido")
    return P - x if x & 1 != segno else x


def _decodifica(b: bytes) -> tuple[int, int, int, int]:
    """Decodifica un punto Ed25519 compresso canonico (senza controllo del sottogruppo)."""
    _require_bytes(b, 32, "punto Ed25519 compresso")
    encoded = int.from_bytes(b, "little")
    sign, y = encoded >> 255, encoded & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("codifica Ed25519 non canonica")
    x = _x_da_y(y, sign)
    if x % P == 0 and sign:   # RFC 8032 5.1.3: x = 0 con bit di segno 1 non è canonico
        raise ValueError("bit di segno Ed25519 non canonico")
    return (x, y, 1, x * y % P)

def _codifica(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _somma(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _moltiplica(k: int, p):
    r = (0, 1, 1, 0)                               # elemento neutro
    while k:
        if k & 1:
            r = _somma(r, p)
        p = _somma(p, p)
        k >>= 1
    return r


# Punto base, nella forma testuale che la specifica inserisce nel calcolo di h.
BASE_STR = (b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, "
            b"46316835694926478169428394003475163141307993866256225615783033603165251855960)")


def fattore_accecante(A: bytes, periodo: int, durata_minuti: int) -> int:
    _require_bytes(A, 32, "chiave identità del servizio")
    _require_u64(periodo, "time period")
    _require_u64(durata_minuti, "durata periodo temporale", positive=True)
    n = b"key-blind" + struct.pack(">QQ", periodo, durata_minuti)
    h = bytearray(hashlib.sha3_256(b"Derive temporary signing key\x00" + A + BASE_STR + n).digest())
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")

def chiave_accecata(A: bytes, periodo: int, durata_minuti: int) -> bytes:
    """A' = h·A: la chiave pubblica del servizio per un certo periodo."""
    return _codifica(_moltiplica(fattore_accecante(A, periodo, durata_minuti), _decodifica(A)))


def credenziale(A: bytes) -> bytes:
    _require_bytes(A, 32, "chiave identità del servizio")
    return hashlib.sha3_256(b"credential" + A).digest()

def sottocredenziale(A: bytes, accecata: bytes) -> bytes:
    _require_bytes(accecata, 32, "chiave accecata del servizio")
    return hashlib.sha3_256(b"subcredential" + credenziale(A) + accecata).digest()

# --- Periodi di tempo e anello degli HSDir ----------------------------------------------

SR_ROUNDS = 12            # SHARED_RANDOM_N_ROUNDS; una "fase" del protocollo di casualità condivisa


@dataclass
class Tempo:
    periodo: int
    durata_minuti: int
    usa_srv_corrente: bool


def tempo(valid_after: int, intervallo_voto: int, rete_di_test: bool) -> Tempo:
    """Ricava il periodo HS dal calendario di voto del consenso."""
    _require_u64(valid_after, "valid-after")
    _require_u64(intervallo_voto, "intervallo di voto", positive=True)
    phase = SR_ROUNDS * intervallo_voto
    if phase < 60 or phase % 60 or 2 * phase >= 2 ** 64:
        raise ValueError("durata fase SRV non valida")
    duration = (2 * phase if rete_di_test else 24 * 3600) // 60
    minutes = valid_after // 60 - phase // 60
    period = minutes // duration
    if period < 0:
        raise ValueError("periodo temporale precedente all'epoca Unix")
    within_cycle = valid_after % (2 * phase)
    return Tempo(period, duration, within_cycle >= phase)

def srv_disastro(t: Tempo) -> bytes:
    _require_u64(t.periodo, "time period")
    _require_u64(t.durata_minuti, "duration", positive=True)
    return hashlib.sha3_256(b"shared-random-disaster" + struct.pack(">QQ", t.durata_minuti, t.periodo)).digest()

def indice_servizio(accecata: bytes, replica: int, t: Tempo) -> bytes:
    _require_bytes(accecata, 32, "chiave accecata del servizio")
    _require_u64(replica, "replica", positive=True)
    _require_u64(t.periodo, "time period")
    _require_u64(t.durata_minuti, "duration", positive=True)
    return hashlib.sha3_256(b"store-at-idx" + accecata + struct.pack(">QQQ", replica, t.durata_minuti, t.periodo)).digest()

def indice_relay(id_ed: bytes, srv: bytes, t: Tempo) -> bytes:
    _require_bytes(id_ed, 32, "identità Ed25519 HSDir")
    _require_bytes(srv, 32, "valore casuale condiviso")
    _require_u64(t.periodo, "time period")
    _require_u64(t.durata_minuti, "duration", positive=True)
    return hashlib.sha3_256(b"node-idx" + id_ed + srv + struct.pack(">QQ", t.periodo, t.durata_minuti)).digest()

def hsdir_responsabili(accecata: bytes, hsdir: list[tuple[str, bytes]], srv: bytes, t: Tempo,
                       repliche: int = 2, spread: int = 3) -> list[list[str]]:
    """Seleziona HSDir distinti per ogni replica; rifiuta anelli insufficienti."""
    _require_bytes(accecata, 32, "chiave accecata del servizio")
    _require_bytes(srv, 32, "valore casuale condiviso")
    if not isinstance(repliche, int) or isinstance(repliche, bool) or repliche <= 0:
        raise ValueError("il numero di repliche deve essere positivo")
    if not isinstance(spread, int) or isinstance(spread, bool) or spread <= 0:
        raise ValueError("la dispersione HSDir deve essere positiva")
    if len(hsdir) < repliche * spread:
        raise ValueError("HSDir insufficienti per repliche distinte")
    names = [name for name, _ in hsdir]
    if len(set(names)) != len(names):
        raise ValueError("nomi HSDir duplicati")
    ring = sorted((indice_relay(ed, srv, t), name) for name, ed in hsdir)
    selected, result = set(), []
    for replica in range(1, repliche + 1):
        idx = indice_servizio(accecata, replica, t)
        start = next((i for i, (x, _) in enumerate(ring) if x > idx), 0)
        group = []
        for k in range(len(ring)):
            name = ring[(start + k) % len(ring)][1]
            if name not in selected:
                group.append(name)
                selected.add(name)
                if len(group) == spread:
                    break
        result.append(group)
    return result

# --- Il descrittore ----------------------------------------------------------------------

def _decifra_strato(blob: bytes, dati_segreti: bytes, subcred: bytes, revisione: int,
                    costante: bytes) -> bytes:
    """Autentica lo strato SALT | CIFRATO | MAC prima della decifratura."""
    if len(blob) < 48:
        raise ValueError("strato cifrato del descrittore troncato")
    _require_bytes(dati_segreti, 32, "segreto del descrittore")
    _require_bytes(subcred, 32, "sottocredenziale del descrittore")
    _require_u64(revisione, "revisione del descrittore")
    sale, cifrato, mac = blob[:16], blob[16:-32], blob[-32:]
    ingresso = dati_segreti + subcred + struct.pack(">Q", revisione) + sale + costante
    chiavi = hashlib.shake_256(ingresso).digest(80)
    k, iv, k_mac = chiavi[:32], chiavi[32:48], chiavi[48:]
    atteso = hashlib.sha3_256(struct.pack(">Q", 32) + k_mac + struct.pack(">Q", 16) + sale
                              + cifrato).digest()
    if not hmac.compare_digest(atteso, mac):
        raise ValueError("MAC del descrittore cifrato non valido")
    d = Cipher(algorithms.AES(k), modes.CTR(iv)).decryptor()
    return (d.update(cifrato) + d.finalize()).rstrip(b"\x00")

def _oggetto(testo: str, parola: str) -> bytes:
    """Estrae un blocco PEM univoco con verifica rigorosa del Base64."""
    lines = testo.splitlines()
    positions = [i for i, line in enumerate(lines) if line == parola]
    if len(positions) != 1:
        raise ValueError("oggetto del descrittore mancante o duplicato")
    pos = positions[0]
    if pos + 2 >= len(lines):
        raise ValueError("oggetto del descrittore troncato")
    begin = lines[pos + 1]
    marker = {"descriptor-signing-key-cert": "ED25519 CERT"}.get(parola, "MESSAGE")
    if begin != f"-----BEGIN {marker}-----":
        raise ValueError("intestazione oggetto del descrittore non valida")
    try:
        end = lines.index(f"-----END {marker}-----", pos + 2)
    except ValueError:
        raise ValueError("oggetto del descrittore non terminato") from None
    encoded = "".join(lines[pos + 2:end])
    if not encoded:
        raise ValueError("oggetto del descrittore vuoto")
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("base64 dell'oggetto descrittore non valido") from None

@dataclass
class Descrittore:
    durata_minuti: int
    revisione: int
    chiave_firma: bytes
    punti_di_introduzione: list[str]
    strato_interno: str


def analizza_descrittore(testo: str, A: bytes, accecata: bytes, *, check_expiration: bool = False,
                     reference_time: float | None = None) -> Descrittore:
    """Analizza un descrittore HSv3 firmato; controlla facoltativamente la scadenza.

    I descrittori storici di laboratorio usano check_expiration=False.
    I client con dati correnti devono verificare la scadenza e autenticare la directory.
    Il modulo didattico non supporta i descrittori restricted discovery.
    """
    _require_bytes(A, 32, "chiave identità del servizio")
    _require_bytes(accecata, 32, "chiave accecata del servizio")
    if not testo.startswith("hs-descriptor 3\n"):
        raise ValueError("versione descrittore onion service non supportata")
    righe = {}
    for row in testo.splitlines():
        if row.startswith(("descriptor-lifetime ", "revision-counter ", "signature ")):
            keyword, value = row.split(" ", 1)
            if keyword in righe:
                raise ValueError("campo descrittore duplicato")
            righe[keyword] = value
    if any(k not in righe for k in ("descriptor-lifetime", "revision-counter", "signature")):
        raise ValueError("campo descrittore mancante")
    lifetime = int(righe["descriptor-lifetime"])
    if not 30 <= lifetime <= 720:
        raise ValueError("durata del descrittore fuori intervallo")
    revisione = int(righe["revision-counter"])
    _require_u64(revisione, "revisione del descrittore")
    signature_marker = "\nsignature "
    if testo.count(signature_marker) != 1 or not testo.splitlines()[-1].startswith("signature "):
        raise ValueError("la firma del descrittore deve essere l'ultima riga")
    subcred = sottocredenziale(A, accecata)
    cert = decodifica_cert_ed(_oggetto(testo, "descriptor-signing-key-cert"))
    if cert.tipo != 0x08 or cert.tipo_chiave != 0x01 or cert.chiave_firmataria != accecata:
        raise ValueError("certificato di firma non associato alla chiave accecata")
    if check_expiration and cert.scaduto(reference_time):
        raise ValueError("certificato di firma del descrittore scaduto")
    cert.verifica_firma(accecata)
    chiave_firma = cert.chiave_certificata
    corpo = testo[:testo.index(signature_marker) + 1].encode("utf-8")
    try:
        firma = base64.b64decode(righe["signature"] + "=" * (-len(righe["signature"]) % 4), validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("base64 della firma del descrittore non valido") from None
    if len(firma) != 64:
        raise ValueError("lunghezza firma descrittore non valida")
    try:
        Ed25519PublicKey.from_public_bytes(chiave_firma).verify(
            firma, b"Tor onion service descriptor sig v3" + corpo)
    except InvalidSignature:
        raise ValueError("firma del descrittore non valida") from None
    esterno = _decifra_strato(_oggetto(testo, "superencrypted"), accecata, subcred, revisione,
                              b"hsdir-superencrypted-data").decode("utf-8")
    interno = _decifra_strato(_oggetto(esterno, "encrypted"), accecata, subcred, revisione,
                              b"hsdir-encrypted-data").decode("utf-8")
    punti = [r.split(" ", 1)[1] for r in interno.splitlines()
                           if r.startswith("introduction-point ")]
    return Descrittore(lifetime, revisione, chiave_firma, punti, interno)

def scarica_descrittore(accecata: bytes, percorso: list) -> str:
    """Scarica un descrittore attraverso `percorso`, con l'HSDir come ultimo relay.

    Un client vero usa tre salti. Con un salto solo è l'HSDir a rifiutare la richiesta
    (HTTP 503, connection_dir_is_anonymous): il Laboratorio 8 lo usa come controllo
    negativo (cap. 14), quindi qui non lo si impedisce. Non certifica l'anonimato.
    """
    _require_bytes(accecata, 32, "chiave accecata del servizio")
    if not percorso:
        raise ValueError("percorso vuoto: serve almeno l'HSDir")
    from .circuito import costruisci
    from .directory import scarica
    url = "/tor/hs/3/" + base64.b64encode(accecata).decode("ascii").rstrip("=")
    return scarica(costruisci(percorso, cc=False), url, 1).decode("utf-8")