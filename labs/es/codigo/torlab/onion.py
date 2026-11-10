# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 8 — servicios onion v3: direcciones, claves cegadas, HSDir y descriptores.

Referencias: rend-spec, codificación de direcciones onion, derivación de claves
cegadas y subcredenciales, ubicación y descarga de descriptores de servicios onion,
formato de cifrado de descriptores y apéndice A (cegado de claves).
Módulo didáctico: usar únicamente en la red privada del libro.
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

from .channel import decode_ed_certificate

 # --- Direcciones .onion -------------------------------------------------------------

VERSION = 3


def _require_bytes(value: bytes, size: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{label} debe contener exactamente {size} bytes")


def _require_u64(value: int, label: str, *, positive: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value < 2 ** 64):
        raise ValueError(f"{label} debe ser un uint64 no negativo")
    if positive and value == 0:
        raise ValueError(f"{label} debe ser positivo")




def onion_address(key: bytes) -> str:
    """Codifica una dirección onion v3 canónica desde una clave pública Ed25519 de 32 bytes."""
    _require_bytes(key, 32, "clave de identidad onion")
    checksum = hashlib.sha3_256(b".onion checksum" + key + bytes([VERSION])).digest()[:2]
    return base64.b32encode(key + checksum + bytes([VERSION])).decode("ascii").lower() + ".onion"

def key_from_address(address: str) -> bytes:
    """Comprueba el nombre, alfabeto Base32, versión y suma de comprobación."""
    if not isinstance(address, str):
        raise ValueError("dirección onion v3 no válida")
    canonical = address.lower()
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", canonical):
        raise ValueError("dirección onion v3 no válida")
    raw = base64.b32decode(canonical[:-6].upper(), casefold=False)
    key, checksum, version = raw[:32], raw[32:34], raw[34]
    if version != VERSION:
        raise ValueError("versión de dirección onion v3 no admitida")
    expected = hashlib.sha3_256(b".onion checksum" + key + bytes([version])).digest()[:2]
    if not hmac.compare_digest(expected, checksum):
        raise ValueError("suma de comprobación onion v3 no válida")
    return key

# --- Aritmética Ed25519 (RFC 8032): solo lo necesario para el cegado de claves ----------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _x_from_y(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * I % P
    if (x * x - xx) % P:
        raise ValueError("punto no válido")
    return P - x if x & 1 != sign else x


def _decode_point(b: bytes) -> tuple[int, int, int, int]:
    """Decodifica un punto Ed25519 comprimido canónico (sin comprobar subgrupos)."""
    _require_bytes(b, 32, "punto Ed25519 comprimido")
    encoded = int.from_bytes(b, "little")
    sign, y = encoded >> 255, encoded & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("codificación Ed25519 no canónica")
    x = _x_from_y(y, sign)
    if x % P == 0 and sign:   # RFC 8032 5.1.3
        raise ValueError("bit de signo Ed25519 no canónico")
    return (x, y, 1, x * y % P)

def _encode_point(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _multiply(k: int, p):
    r = (0, 1, 1, 0)                               # elemento neutro
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


# Punto base en la representación textual de la especificación para calcular h.
BASE_STR = (b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, "
            b"46316835694926478169428394003475163141307993866256225615783033603165251855960)")


def blinding_factor(A: bytes, period: int, duration_minutes: int) -> int:
    _require_bytes(A, 32, "clave de identidad del servicio")
    _require_u64(period, "time period")
    _require_u64(duration_minutes, "duración del período", positive=True)
    n = b"key-blind" + struct.pack(">QQ", period, duration_minutes)
    h = bytearray(hashlib.sha3_256(b"Derive temporary signing key\x00" + A + BASE_STR + n).digest())
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")

def blinded_key(A: bytes, period: int, duration_minutes: int) -> bytes:
    """A' = h·A: clave pública del servicio para un período determinado."""
    return _encode_point(_multiply(blinding_factor(A, period, duration_minutes), _decode_point(A)))


def credential(A: bytes) -> bytes:
    _require_bytes(A, 32, "clave de identidad del servicio")
    return hashlib.sha3_256(b"credential" + A).digest()

def subcredential(A: bytes, blinded: bytes) -> bytes:
    _require_bytes(blinded, 32, "clave cegada del servicio")
    return hashlib.sha3_256(b"subcredential" + credential(A) + blinded).digest()

# --- Períodos temporales y anillo HSDir ----------------------------------------------

SR_ROUNDS = 12            # SHARED_RANDOM_N_ROUNDS; una fase del protocolo de aleatoriedad compartida


@dataclass
class TimePeriodInfo:
    period: int
    duration_minutes: int
    uses_current_srv: bool


def time_period_info(valid_after: int, voting_interval: int, test_network: bool) -> TimePeriodInfo:
    """Calcula el período HS según el calendario de votación del consenso."""
    _require_u64(valid_after, "valid-after")
    _require_u64(voting_interval, "intervalo de votación", positive=True)
    phase = SR_ROUNDS * voting_interval
    if phase < 60 or phase % 60 or 2 * phase >= 2 ** 64:
        raise ValueError("duración de fase SRV no válida")
    duration = (2 * phase if test_network else 24 * 3600) // 60
    minutes = valid_after // 60 - phase // 60
    period = minutes // duration
    if period < 0:
        raise ValueError("período anterior a la época Unix")
    within_cycle = valid_after % (2 * phase)
    return TimePeriodInfo(period, duration, within_cycle >= phase)

def disaster_srv(t: TimePeriodInfo) -> bytes:
    _require_u64(t.period, "time period")
    _require_u64(t.duration_minutes, "duration", positive=True)
    return hashlib.sha3_256(b"shared-random-disaster" + struct.pack(">QQ", t.duration_minutes, t.period)).digest()

def service_index(blinded: bytes, replica: int, t: TimePeriodInfo) -> bytes:
    _require_bytes(blinded, 32, "clave cegada del servicio")
    _require_u64(replica, "replica", positive=True)
    _require_u64(t.period, "time period")
    _require_u64(t.duration_minutes, "duration", positive=True)
    return hashlib.sha3_256(b"store-at-idx" + blinded + struct.pack(">QQQ", replica, t.duration_minutes, t.period)).digest()

def relay_index(id_ed: bytes, srv: bytes, t: TimePeriodInfo) -> bytes:
    _require_bytes(id_ed, 32, "identidad Ed25519 HSDir")
    _require_bytes(srv, 32, "valor aleatorio compartido")
    _require_u64(t.period, "time period")
    _require_u64(t.duration_minutes, "duration", positive=True)
    return hashlib.sha3_256(b"node-idx" + id_ed + srv + struct.pack(">QQ", t.period, t.duration_minutes)).digest()

def responsible_hsdirs(blinded: bytes, hsdir: list[tuple[str, bytes]], srv: bytes, t: TimePeriodInfo,
                       replicas: int = 2, spread: int = 3) -> list[list[str]]:
    """Elige HSDir distintos para cada réplica; rechaza anillos insuficientes."""
    _require_bytes(blinded, 32, "clave cegada del servicio")
    _require_bytes(srv, 32, "valor aleatorio compartido")
    if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas <= 0:
        raise ValueError("el número de réplicas debe ser positivo")
    if not isinstance(spread, int) or isinstance(spread, bool) or spread <= 0:
        raise ValueError("la dispersión HSDir debe ser positiva")
    if len(hsdir) < replicas * spread:
        raise ValueError("HSDir insuficientes para réplicas distintas")
    names = [name for name, _ in hsdir]
    if len(set(names)) != len(names):
        raise ValueError("nombres HSDir duplicados")
    ring = sorted((relay_index(ed, srv, t), name) for name, ed in hsdir)
    selected, result = set(), []
    for replica in range(1, replicas + 1):
        idx = service_index(blinded, replica, t)
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

# --- El descriptor ----------------------------------------------------------------------

def _decrypt_layer(blob: bytes, secret_data: bytes, subcred: bytes, revision: int,
                    constant: bytes) -> bytes:
    """Autentica la capa SALT | CIFRADO | MAC antes de descifrar."""
    if len(blob) < 48:
        raise ValueError("capa cifrada del descriptor truncada")
    _require_bytes(secret_data, 32, "secreto del descriptor")
    _require_bytes(subcred, 32, "subcredencial del descriptor")
    _require_u64(revision, "revisión del descriptor")
    salt, ciphertext, mac = blob[:16], blob[16:-32], blob[-32:]
    input_data = secret_data + subcred + struct.pack(">Q", revision) + salt + constant
    keys = hashlib.shake_256(input_data).digest(80)
    k, iv, k_mac = keys[:32], keys[32:48], keys[48:]
    expected = hashlib.sha3_256(struct.pack(">Q", 32) + k_mac + struct.pack(">Q", 16) + salt
                              + ciphertext).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("MAC del descriptor cifrado no válido")
    d = Cipher(algorithms.AES(k), modes.CTR(iv)).decryptor()
    return (d.update(ciphertext) + d.finalize()).rstrip(b"\x00")

def _object_block(text: str, keyword: str) -> bytes:
    """Extrae un bloque PEM único con comprobación estricta de Base64."""
    lines = text.splitlines()
    positions = [i for i, line in enumerate(lines) if line == keyword]
    if len(positions) != 1:
        raise ValueError("objeto del descriptor ausente o duplicado")
    pos = positions[0]
    if pos + 2 >= len(lines):
        raise ValueError("objeto del descriptor truncado")
    begin = lines[pos + 1]
    marker = {"descriptor-signing-key-cert": "ED25519 CERT"}.get(keyword, "MESSAGE")
    if begin != f"-----BEGIN {marker}-----":
        raise ValueError("cabecera del objeto del descriptor no válida")
    try:
        end = lines.index(f"-----END {marker}-----", pos + 2)
    except ValueError:
        raise ValueError("objeto del descriptor sin terminar") from None
    encoded = "".join(lines[pos + 2:end])
    if not encoded:
        raise ValueError("objeto del descriptor vacío")
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("base64 del objeto del descriptor no válido") from None

@dataclass
class Descriptor:
    duration_minutes: int
    revision: int
    signing_key: bytes
    introduction_points: list[str]
    inner_layer: str


def parse_descriptor(text: str, A: bytes, blinded: bytes, *, check_expiration: bool = False,
                     reference_time: float | None = None) -> Descriptor:
    """Analiza un descriptor HSv3 firmado y comprueba opcionalmente la caducidad.

    Las muestras históricas usan check_expiration=False.
    Los clientes actuales deben validar la caducidad y autenticar el directorio.
    Este decodificador didáctico no admite restricted discovery.
    """
    _require_bytes(A, 32, "clave de identidad del servicio")
    _require_bytes(blinded, 32, "clave cegada del servicio")
    if not text.startswith("hs-descriptor 3\n"):
        raise ValueError("versión de descriptor del servicio onion no admitida")
    lines = {}
    for row in text.splitlines():
        if row.startswith(("descriptor-lifetime ", "revision-counter ", "signature ")):
            keyword, value = row.split(" ", 1)
            if keyword in lines:
                raise ValueError("campo del descriptor duplicado")
            lines[keyword] = value
    if any(k not in lines for k in ("descriptor-lifetime", "revision-counter", "signature")):
        raise ValueError("campo del descriptor ausente")
    lifetime = int(lines["descriptor-lifetime"])
    if not 30 <= lifetime <= 720:
        raise ValueError("duración del descriptor fuera de rango")
    revision = int(lines["revision-counter"])
    _require_u64(revision, "revisión del descriptor")
    signature_marker = "\nsignature "
    if text.count(signature_marker) != 1 or not text.splitlines()[-1].startswith("signature "):
        raise ValueError("la firma del descriptor debe ser la última línea")
    subcred = subcredential(A, blinded)
    cert = decode_ed_certificate(_object_block(text, "descriptor-signing-key-cert"))
    if cert.kind != 0x08 or cert.key_type != 0x01 or cert.signing_key != blinded:
        raise ValueError("certificado de firma no vinculado a la clave cegada")
    if check_expiration and cert.expired(reference_time):
        raise ValueError("certificado de firma del descriptor caducado")
    cert.verify_signature(blinded)
    signing_key = cert.certified_key
    body = text[:text.index(signature_marker) + 1].encode("utf-8")
    try:
        signature = base64.b64decode(lines["signature"] + "=" * (-len(lines["signature"]) % 4), validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("base64 de firma del descriptor no válido") from None
    if len(signature) != 64:
        raise ValueError("longitud de firma del descriptor no válida")
    try:
        Ed25519PublicKey.from_public_bytes(signing_key).verify(
            signature, b"Tor onion service descriptor sig v3" + body)
    except InvalidSignature:
        raise ValueError("firma del descriptor no válida") from None
    outer = _decrypt_layer(_object_block(text, "superencrypted"), blinded, subcred, revision,
                              b"hsdir-superencrypted-data").decode("utf-8")
    inner = _decrypt_layer(_object_block(outer, "encrypted"), blinded, subcred, revision,
                              b"hsdir-encrypted-data").decode("utf-8")
    introduction_points = [r.split(" ", 1)[1] for r in inner.splitlines()
                           if r.startswith("introduction-point ")]
    return Descriptor(lifetime, revision, signing_key, introduction_points, inner)

def download_descriptor(blinded: bytes, path: list) -> str:
    """Descarga el descriptor mediante un circuito HSDir anónimo dedicado.

    Se exigen tres saltos; no se certifica anonimato en la red pública.
    """
    _require_bytes(blinded, 32, "clave cegada del servicio")
    if len(path) < 3:
        raise ValueError("La petición HSDir necesita al menos tres saltos")
    from .circuit import build
    from .directory import download
    url = "/tor/hs/3/" + base64.b64encode(blinded).decode("ascii").rstrip("=")
    return download(build(path, cc=False), url, 1).decode("utf-8")