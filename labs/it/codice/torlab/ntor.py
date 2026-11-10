# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 3 — handshake di creazione dei circuiti: CREATE_FAST, ntor, ntor-v3.

Riferimenti: tor-spec, "Creating and extending circuits" e "Setting circuit keys";
proposte 216 (ntor) e 332 (ntor-v3). Modulo didattico: solo per la rete privata del libro.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HTYPE_TAP, HTYPE_NTOR, HTYPE_NTOR_V3 = 0, 2, 3

# Chiavi per la cifratura "tor1" dei relay cell: Df, Db (SHA-1), Kf, Kb (AES-128).
LUNGHEZZA_CHIAVI_CIRCUITO = 20 + 20 + 16 + 16      # CPATH_KEY_MATERIAL_LEN in tor

# Stringa di verifica usata da tor per ntor-v3 sui circuiti ordinari
# (NTOR3_CIRC_VERIFICATION in src/core/crypto/onion_crypto.c).
VER_CIRCUITO = b"circuit extend"


class ErroreHandshake(Exception):
    """La risposta del relay non supera le verifiche dell'handshake."""


@dataclass
class ChiaviCircuito:
    Df: bytes   # seme del digest in avanti (client -> relay)
    Db: bytes   # seme del digest all'indietro
    Kf: bytes   # chiave AES in avanti
    Kb: bytes   # chiave AES all'indietro

    @classmethod
    def da_flusso(cls, k: bytes) -> "ChiaviCircuito":
        _require_length(k, LUNGHEZZA_CHIAVI_CIRCUITO, "tor1 key stream")
        return cls(k[0:20], k[20:40], k[40:56], k[56:72])


# --- Primitive ---------------------------------------------------------------

def _require_length(value: bytes, size: int, label: str) -> None:
    """Verifica le lunghezze esatte dei campi dell'handshake."""
    if len(value) != size:
        raise ErroreHandshake(f"{label}: expected {size} bytes, got {len(value)}")


def x25519_genera(privata: bytes | None = None) -> tuple[X25519PrivateKey, bytes]:
    sk = (X25519PrivateKey.generate() if privata is None
          else X25519PrivateKey.from_private_bytes(privata))
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_dh(sk: X25519PrivateKey, pub: bytes) -> bytes:
    _require_length(pub, 32, "X25519 public key")
    try:
        condiviso = sk.exchange(X25519PublicKey.from_public_bytes(pub))
    except ValueError as exc:
        raise ErroreHandshake("chiave pubblica X25519 non valida") from exc
    if condiviso == bytes(32):
        # Il "punto all'infinito": l'altra parte ha inviato una chiave degenere.
        raise ErroreHandshake("risultato Diffie-Hellman nullo")
    return condiviso


def aes_ctr(chiave: bytes, dati: bytes) -> bytes:
    """AES in modalità contatore con IV a zero (tor-spec, "Ciphers")."""
    if len(chiave) not in (16, 32):
        raise ErroreHandshake("AES-CTR richiede una chiave di 16 o 32 byte")
    c = Cipher(algorithms.AES(chiave), modes.CTR(bytes(16))).encryptor()
    return c.update(dati) + c.finalize()


# --- KDF-TOR e CREATE_FAST ------------------------------------------------------

def kdf_tor(k0: bytes, lunghezza: int) -> bytes:
    """K = SHA1(K0|00) | SHA1(K0|01) | ... (al massimo 5120 byte)."""
    if isinstance(lunghezza, bool) or not isinstance(lunghezza, int) or not 0 <= lunghezza <= 5120:
        raise ValueError("lunghezza KDF-TOR ammessa: 0–5120")
    uscita = b"".join(hashlib.sha1(k0 + bytes([i])).digest() for i in range(-(-lunghezza // 20)))
    return uscita[:lunghezza]


def create_fast_client() -> tuple[bytes, bytes]:
    """Restituisce (stato, corpo di CREATE_FAST): 20 byte casuali X."""
    x = os.urandom(20)
    return x, x


def create_fast_completa(x: bytes, corpo_created_fast: bytes) -> ChiaviCircuito:
    """CREATED_FAST = Y (20) | KH (20). Da K0 = X|Y si ricavano KH, Df, Db, Kf, Kb.

    Il corpo è quello di una cella fissa (509 byte): dopo i 40 byte utili c'è il riempimento,
    che tor ignora (onion.c copia solo CREATED_FAST_LEN byte)."""
    _require_length(x, 20, "CREATE_FAST X")
    if len(corpo_created_fast) < 40:
        raise ErroreHandshake(f"CREATED_FAST body: expected at least 40 bytes, got {len(corpo_created_fast)}")
    y, kh = corpo_created_fast[:20], corpo_created_fast[20:40]
    k = kdf_tor(x + y, 20 + LUNGHEZZA_CHIAVI_CIRCUITO)
    if not hmac.compare_digest(k[:20], kh):
        raise ErroreHandshake("KH non corrisponde: il relay non conosce la chiave")
    return ChiaviCircuito.da_flusso(k[20:])


# --- ntor (proposta 216) ------------------------------------------------------

NTOR_PROTOID = b"ntor-curve25519-sha256-1"
NTOR_T_MAC = NTOR_PROTOID + b":mac"
NTOR_T_KEY = NTOR_PROTOID + b":key_extract"
NTOR_T_VERIFY = NTOR_PROTOID + b":verify"
NTOR_M_EXPAND = NTOR_PROTOID + b":key_expand"


def _h(x: bytes, t: bytes) -> bytes:
    return hmac.new(t, x, hashlib.sha256).digest()


def kdf_rfc5869(key_seed: bytes, info: bytes, lunghezza: int) -> bytes:
    """Fase di espansione di HKDF-SHA256 con chiave KEY_SEED."""
    if isinstance(lunghezza, bool) or not isinstance(lunghezza, int) or not 0 <= lunghezza <= 8160:
        raise ValueError("lunghezza HKDF-SHA256 ammessa: 0–8160")
    uscita, blocco, i = b"", b"", 1
    while len(uscita) < lunghezza:
        blocco = _h(blocco + info + bytes([i]), key_seed)
        uscita += blocco
        i += 1
    return uscita[:lunghezza]


@dataclass
class StatoNtor:
    x: X25519PrivateKey
    X: bytes
    B: bytes
    nodeid: bytes


def ntor_client_inizio(nodeid_rsa: bytes, B: bytes, x: bytes | None = None) -> tuple[StatoNtor, bytes]:
    """HDATA di CREATE2 per ntor: NODEID (20) | KEYID = B (32) | X (32)."""
    _require_length(nodeid_rsa, 20, "ntor NODEID")
    _require_length(B, 32, "ntor onion key")
    sk, X = x25519_genera(x)
    return StatoNtor(sk, X, B, nodeid_rsa), nodeid_rsa + B + X


def ntor_client_fine(st: StatoNtor, risposta: bytes, lunghezza=LUNGHEZZA_CHIAVI_CIRCUITO) -> bytes:
    """Verifica AUTH nella risposta (Y | AUTH) e restituisce il flusso di chiavi."""
    _require_length(risposta, 64, "ntor server response")
    Y, auth = risposta[:32], risposta[32:64]
    secret_input = (x25519_dh(st.x, Y) + x25519_dh(st.x, st.B) + st.nodeid
                    + st.B + st.X + Y + NTOR_PROTOID)
    key_seed = _h(secret_input, NTOR_T_KEY)
    verify = _h(secret_input, NTOR_T_VERIFY)
    auth_input = verify + st.nodeid + st.B + Y + st.X + NTOR_PROTOID + b"Server"
    if not hmac.compare_digest(_h(auth_input, NTOR_T_MAC), auth):
        raise ErroreHandshake("AUTH ntor non valido")
    return kdf_rfc5869(key_seed, NTOR_M_EXPAND, lunghezza)


# --- ntor-v3 (proposta 332) ---------------------------------------------------

NTOR3_PROTOID = b"ntor3-curve25519-sha3_256-1"


def _t(nome: str) -> bytes:
    return NTOR3_PROTOID + b":" + nome.encode()


def _encap(s: bytes) -> bytes:
    return struct.pack(">Q", len(s)) + s


def _h3(s: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + s).digest()


def _mac3(k: bytes, msg: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + _encap(k) + msg).digest()


def _kdf3(s: bytes, t: bytes, lunghezza: int) -> bytes:
    if isinstance(lunghezza, bool) or not isinstance(lunghezza, int) or lunghezza < 0:
        raise ValueError("lunghezza output SHAKE256 non valida")
    return hashlib.shake_256(_encap(t) + s).digest(lunghezza)


@dataclass
class StatoNtor3:
    x: X25519PrivateKey
    X: bytes
    B: bytes
    ID: bytes
    Bx: bytes
    mac: bytes
    ver: bytes


def ntor3_client_inizio(ID: bytes, B: bytes, messaggio: bytes, ver: bytes = VER_CIRCUITO,
                        x: bytes | None = None) -> tuple[StatoNtor3, bytes]:
    """HDATA di CREATE2 per ntor-v3: ID (32) | B (32) | X (32) | MSG cifrato | MAC (32)."""
    _require_length(ID, 32, "ntor-v3 Ed25519 ID")
    _require_length(B, 32, "ntor-v3 onion key")
    sk, X = x25519_genera(x)
    Bx = x25519_dh(sk, B)
    fase1 = _kdf3(Bx + ID + X + B + NTOR3_PROTOID + _encap(ver), _t("kdf_phase1"), 64)
    enc_k1, mac_k1 = fase1[:32], fase1[32:]
    msg_cifrato = aes_ctr(enc_k1, messaggio)          # AES-256-CTR
    mac = _mac3(mac_k1, ID + B + X + msg_cifrato, _t("msg_mac"))
    return StatoNtor3(sk, X, B, ID, Bx, mac, ver), ID + B + X + msg_cifrato + mac


def ntor3_client_fine(st: StatoNtor3, risposta: bytes,
                      lunghezza=LUNGHEZZA_CHIAVI_CIRCUITO) -> tuple[bytes, bytes]:
    """Risposta = Y (32) | AUTH (32) | MSG. Restituisce (messaggio del relay, flusso di chiavi)."""
    if len(risposta) < 64:
        raise ErroreHandshake("risposta ntor-v3 troncata")
    Y, auth, msg = risposta[:32], risposta[32:64], risposta[64:]
    secret_input = (x25519_dh(st.x, Y) + st.Bx + st.ID + st.B + st.X + Y
                    + NTOR3_PROTOID + _encap(st.ver))
    key_seed = _h3(secret_input, _t("key_seed"))
    verify = _h3(secret_input, _t("verify"))
    auth_input = (verify + st.ID + st.B + Y + st.X + st.mac + _encap(msg)
                  + NTOR3_PROTOID + b"Server")
    if not hmac.compare_digest(_h3(auth_input, _t("auth_final")), auth):
        raise ErroreHandshake("AUTH ntor-v3 non valido")
    flusso = _kdf3(key_seed, _t("kdf_final"), 32 + lunghezza)
    return aes_ctr(flusso[:32], msg), flusso[32:]


# --- Estensioni e celle -------------------------------------------------------

def codifica_estensioni(estensioni: list[tuple[int, bytes]]) -> bytes:
    """N_EXTENSIONS | (type, length, dati)*."""
    if len(estensioni) > 255:
        raise ErroreHandshake("too many handshake estensioni")
    out = bytearray([len(estensioni)])
    for kind, item in estensioni:
        if isinstance(kind, bool) or not isinstance(kind, int) or not 0 <= kind <= 255 or len(item) > 255:
            raise ErroreHandshake("tipo o lunghezza estensione non validi")
        out.extend((kind, len(item)))
        out.extend(item)
    return bytes(out)


def decodifica_estensioni(dati: bytes) -> list[tuple[int, bytes]]:
    """Reject intestazione estensione troncatas, bodies, and trailing bytes."""
    if not dati:
        raise ErroreHandshake("numero di estensioni mancante")
    count, pos, out = dati[0], 1, []
    for _ in range(count):
        if pos + 2 > len(dati):
            raise ErroreHandshake("intestazione estensione troncata")
        kind, size = dati[pos], dati[pos + 1]
        pos += 2
        if pos + size > len(dati):
            raise ErroreHandshake("truncated extension dati")
        out.append((kind, dati[pos:pos + size]))
        pos += size
    if pos != len(dati):
        raise ErroreHandshake("byte residui nelle estensioni")
    return out


def corpo_create2(htype: int, hdata: bytes) -> bytes:
    """Corpo CREATE2: quattro byte di intestazione in una cella fissa di 509."""
    if isinstance(htype, bool) or not isinstance(htype, int) or not 0 <= htype <= 65535:
        raise ErroreHandshake("tipo handshake CREATE2 non valido")
    if len(hdata) > 505:
        raise ErroreHandshake("HDATA di CREATE2 supera 505 byte")
    return struct.pack(">HH", htype, len(hdata)) + hdata


def hdata_created2(corpo: bytes) -> bytes:
    if len(corpo) < 2:
        raise ErroreHandshake("campo lunghezza CREATED2 troncato")
    (hlen,) = struct.unpack(">H", corpo[:2])
    if len(corpo) < 2 + hlen:
        raise ErroreHandshake("dati handshake CREATED2 troncati")
    return corpo[2:2 + hlen]


def corpo_extend2(ipv4: str, porta: int, id_rsa: bytes, id_ed: bytes,
                  htype: int, hdata: bytes) -> bytes:
    """EXTEND2 con specificatori [00], [02], [03] nell'ordine previsto."""
    try:
        ip = ipaddress.IPv4Address(ipv4).packed
    except ipaddress.AddressValueError as exc:
        raise ErroreHandshake("indirizzo IPv4 EXTEND2 non valido") from exc
    if isinstance(porta, bool) or not isinstance(porta, int) or not 1 <= porta <= 65535:
        raise ErroreHandshake("porta ORPort EXTEND2 non valida")
    _require_length(id_rsa, 20, "identità RSA EXTEND2")
    _require_length(id_ed, 32, "identità Ed25519 EXTEND2")
    spec = [(0x00, ip + struct.pack(">H", porta)), (0x02, id_rsa), (0x03, id_ed)]
    payload = (bytes([len(spec)]) + b"".join(bytes([t, len(d)]) + d for t, d in spec)
               + corpo_create2(htype, hdata))
    if len(payload) > 498:
        raise ErroreHandshake("EXTEND2 supera i 498 byte di dati del relay tor1")
    return payload
