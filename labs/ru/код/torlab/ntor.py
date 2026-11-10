# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 3 — рукопожатия создания цепи: CREATE_FAST, ntor и ntor-v3.

Источники: tor-spec, «Создание и расширение цепей» и «Вывод ключей цепи»;
предложения 216 (ntor) и 332 (ntor-v3). Учебный модуль только для частной сети книги.
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

# Ключи tor1 для relay-cell encryption: Df, Db (SHA-1), Kf, Kb (AES-128).
CIRCUIT_KEY_MATERIAL_LEN = 20 + 20 + 16 + 16      # CPATH_KEY_MATERIAL_LEN in tor

# Verification string, используемая tor для ntor-v3 на обычных circuits
# (NTOR3_CIRC_VERIFICATION в src/core/crypto/onion_crypto.c).
CIRCUIT_VERIFICATION = b"circuit extend"


class HandshakeError(Exception):
    """Ответ relay не прошёл проверки handshake."""


@dataclass
class CircuitKeys:
    Df: bytes   # начальное состояние прямого дайджеста (клиент → ретранслятор)
    Db: bytes   # начальное состояние обратного дайджеста
    Kf: bytes   # ключ AES прямого направления
    Kb: bytes   # ключ AES обратного направления

    @classmethod
    def from_stream(cls, k: bytes) -> "CircuitKeys":
        _require_length(k, CIRCUIT_KEY_MATERIAL_LEN, "tor1 key stream")
        return cls(k[0:20], k[20:40], k[40:56], k[56:72])


def _require_length(value: bytes, size: int, label: str) -> None:
    """Отклоняет некорректные поля до криптографических операций."""
    if len(value) != size:
        raise HandshakeError(f"{label}: expected {size} bytes, got {len(value)}")


# --- Primitive ---------------------------------------------------------------

def x25519_generate(private_key: bytes | None = None) -> tuple[X25519PrivateKey, bytes]:
    sk = (X25519PrivateKey.generate() if private_key is None
          else X25519PrivateKey.from_private_bytes(private_key))
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_dh(sk: X25519PrivateKey, pub: bytes) -> bytes:
    _require_length(pub, 32, "X25519 public key")
    try:
        shared = sk.exchange(X25519PublicKey.from_public_bytes(pub))
    except ValueError as exc:
        raise HandshakeError("недопустимый открытый ключ X25519") from exc
    if shared == bytes(32):
        # Точка на бесконечности: peer прислал вырожденный ключ.
        raise HandshakeError("результат Diffie-Hellman полностью нулевой")
    return shared


def aes_ctr(key: bytes, data: bytes) -> bytes:
    """AES в counter mode с нулевым IV (tor-spec, "Ciphers")."""
    if len(key) not in (16, 32):
        raise HandshakeError("AES-CTR требует ключ длиной 16 или 32 байта")
    c = Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()
    return c.update(data) + c.finalize()


 # --- KDF-TOR и CREATE_FAST --------------------------------------------------------

def kdf_tor(k0: bytes, length: int) -> bytes:
    """K = SHA1(K0|00) | SHA1(K0|01) | ... (не более 5120 байт)."""
    if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= 5120:
        raise ValueError("длина KDF-TOR должна быть в пределах 0–5120")
    output = b"".join(hashlib.sha1(k0 + bytes([i])).digest() for i in range(-(-length // 20)))
    return output[:length]


def create_fast_client() -> tuple[bytes, bytes]:
    """Вернуть (state, CREATE_FAST body): 20 случайных байт X."""
    x = os.urandom(20)
    return x, x


def complete_create_fast(x: bytes, created_fast_body: bytes) -> CircuitKeys:
    """CREATED_FAST = Y (20) | KH (20). K0 = X|Y выводит KH, Df, Db, Kf, Kb."""
    _require_length(x, 20, "CREATE_FAST X")
    _require_length(created_fast_body, 40, "CREATED_FAST body")
    y, kh = created_fast_body[:20], created_fast_body[20:40]
    k = kdf_tor(x + y, 20 + CIRCUIT_KEY_MATERIAL_LEN)
    if not hmac.compare_digest(k[:20], kh):
        raise HandshakeError("KH не совпадает: relay не знает ключ")
    return CircuitKeys.from_stream(k[20:])


 # --- ntor (proposal 216) ------------------------------------------------------

NTOR_PROTOID = b"ntor-curve25519-sha256-1"
NTOR_T_MAC = NTOR_PROTOID + b":mac"
NTOR_T_KEY = NTOR_PROTOID + b":key_extract"
NTOR_T_VERIFY = NTOR_PROTOID + b":verify"
NTOR_M_EXPAND = NTOR_PROTOID + b":key_expand"


def _h(x: bytes, t: bytes) -> bytes:
    return hmac.new(t, x, hashlib.sha256).digest()


def kdf_rfc5869(key_seed: bytes, info: bytes, length: int) -> bytes:
    """Фаза расширения HKDF-SHA256 с использованием KEY_SEED."""
    if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= 8160:
        raise ValueError("длина HKDF-SHA256 должна быть в пределах 0–8160")
    output, block, i = b"", b"", 1
    while len(output) < length:
        block = _h(block + info + bytes([i]), key_seed)
        output += block
        i += 1
    return output[:length]


@dataclass
class NtorState:
    x: X25519PrivateKey
    X: bytes
    B: bytes
    nodeid: bytes


def ntor_client_start(nodeid_rsa: bytes, B: bytes, x: bytes | None = None) -> tuple[NtorState, bytes]:
    """CREATE2 HDATA для ntor: NODEID (20) | KEYID = B (32) | X (32)."""
    _require_length(nodeid_rsa, 20, "ntor NODEID")
    _require_length(B, 32, "ntor onion key")
    sk, X = x25519_generate(x)
    return NtorState(sk, X, B, nodeid_rsa), nodeid_rsa + B + X


def ntor_client_finish(st: NtorState, response: bytes, length=CIRCUIT_KEY_MATERIAL_LEN) -> bytes:
    """Проверить AUTH в ответе (Y | AUTH) и вернуть key stream."""
    _require_length(response, 64, "ntor server response")
    Y, auth = response[:32], response[32:64]
    secret_input = (x25519_dh(st.x, Y) + x25519_dh(st.x, st.B) + st.nodeid
                    + st.B + st.X + Y + NTOR_PROTOID)
    key_seed = _h(secret_input, NTOR_T_KEY)
    verify = _h(secret_input, NTOR_T_VERIFY)
    auth_input = verify + st.nodeid + st.B + Y + st.X + NTOR_PROTOID + b"Server"
    if not hmac.compare_digest(_h(auth_input, NTOR_T_MAC), auth):
        raise HandshakeError("некорректный ntor AUTH")
    return kdf_rfc5869(key_seed, NTOR_M_EXPAND, length)


 # --- ntor-v3 (proposal 332) ---------------------------------------------------

NTOR3_PROTOID = b"ntor3-curve25519-sha3_256-1"


def _t(name: str) -> bytes:
    return NTOR3_PROTOID + b":" + name.encode()


def _encap(s: bytes) -> bytes:
    return struct.pack(">Q", len(s)) + s


def _h3(s: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + s).digest()


def _mac3(k: bytes, msg: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + _encap(k) + msg).digest()


def _kdf3(s: bytes, t: bytes, length: int) -> bytes:
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise ValueError("неверная длина вывода SHAKE256")
    return hashlib.shake_256(_encap(t) + s).digest(length)


@dataclass
class Ntor3State:
    x: X25519PrivateKey
    X: bytes
    B: bytes
    ID: bytes
    Bx: bytes
    mac: bytes
    ver: bytes


def ntor3_client_start(ID: bytes, B: bytes, message: bytes, ver: bytes = CIRCUIT_VERIFICATION,
                        x: bytes | None = None) -> tuple[Ntor3State, bytes]:
    """CREATE2 HDATA для ntor-v3: ID (32) | B (32) | X (32) | encrypted MSG | MAC (32)."""
    _require_length(ID, 32, "ntor-v3 Ed25519 ID")
    _require_length(B, 32, "ntor-v3 onion key")
    sk, X = x25519_generate(x)
    Bx = x25519_dh(sk, B)
    fase1 = _kdf3(Bx + ID + X + B + NTOR3_PROTOID + _encap(ver), _t("kdf_phase1"), 64)
    enc_k1, mac_k1 = fase1[:32], fase1[32:]
    msg_cifrato = aes_ctr(enc_k1, message)          # AES-256-CTR
    mac = _mac3(mac_k1, ID + B + X + msg_cifrato, _t("msg_mac"))
    return Ntor3State(sk, X, B, ID, Bx, mac, ver), ID + B + X + msg_cifrato + mac


def ntor3_client_finish(st: Ntor3State, response: bytes,
                      length=CIRCUIT_KEY_MATERIAL_LEN) -> tuple[bytes, bytes]:
    """Ответ = Y (32) | AUTH (32) | MSG. Вернуть (relay message, key stream)."""
    if len(response) < 64:
        raise HandshakeError("усечённый ответ сервера ntor-v3")
    Y, auth, msg = response[:32], response[32:64], response[64:]
    secret_input = (x25519_dh(st.x, Y) + st.Bx + st.ID + st.B + st.X + Y
                    + NTOR3_PROTOID + _encap(st.ver))
    key_seed = _h3(secret_input, _t("key_seed"))
    verify = _h3(secret_input, _t("verify"))
    auth_input = (verify + st.ID + st.B + Y + st.X + st.mac + _encap(msg)
                  + NTOR3_PROTOID + b"Server")
    if not hmac.compare_digest(_h3(auth_input, _t("auth_final")), auth):
        raise HandshakeError("некорректный ntor-v3 AUTH")
    stream = _kdf3(key_seed, _t("kdf_final"), 32 + length)
    return aes_ctr(stream[:32], msg), stream[32:]


# --- Extensions и cells ---------------------------------------------------------

def encode_extensions(extensions: list[tuple[int, bytes]]) -> bytes:
    """N_EXTENSIONS | (type, length, data)*."""
    if len(extensions) > 255:
        raise HandshakeError("слишком много расширений рукопожатия")
    out = bytearray([len(extensions)])
    for kind, item in extensions:
        if isinstance(kind, bool) or not isinstance(kind, int) or not 0 <= kind <= 255 or len(item) > 255:
            raise HandshakeError("неверный тип или длина расширения")
        out.extend((kind, len(item)))
        out.extend(item)
    return bytes(out)


def decode_extensions(data: bytes) -> list[tuple[int, bytes]]:
    """Reject усечённый заголовок расширенияs, bodies, and trailing bytes."""
    if not data:
        raise HandshakeError("отсутствует счётчик расширений")
    count, pos, out = data[0], 1, []
    for _ in range(count):
        if pos + 2 > len(data):
            raise HandshakeError("усечённый заголовок расширения")
        kind, size = data[pos], data[pos + 1]
        pos += 2
        if pos + size > len(data):
            raise HandshakeError("усечённые данные расширения")
        out.append((kind, data[pos:pos + size]))
        pos += size
    if pos != len(data):
        raise HandshakeError("лишние байты после расширений")
    return out


def create2_body(htype: int, hdata: bytes) -> bytes:
    if isinstance(htype, bool) or not isinstance(htype, int) or not 0 <= htype <= 65535 or len(hdata) > 65535:
        raise HandshakeError("тип или длина данных CREATE2 вне диапазона")
    return struct.pack(">HH", htype, len(hdata)) + hdata


def hdata_created2(body: bytes) -> bytes:
    if len(body) < 2:
        raise HandshakeError("усечённое поле длины CREATED2")
    (hlen,) = struct.unpack(">H", body[:2])
    if len(body) < 2 + hlen:
        raise HandshakeError("усечённые данные рукопожатия CREATED2")
    return body[2:2 + hlen]


def extend2_body(ipv4: str, port: int, id_rsa: bytes, id_ed: bytes,
                  htype: int, hdata: bytes) -> bytes:
    """EXTEND2 со спецификаторами [00], [02], [03] в рекомендуемом порядке."""
    try:
        ip = ipaddress.IPv4Address(ipv4).packed
    except ipaddress.AddressValueError as exc:
        raise HandshakeError("недопустимый IPv4-адрес EXTEND2") from exc
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise HandshakeError("недопустимый ORPort EXTEND2")
    _require_length(id_rsa, 20, "RSA-идентификатор EXTEND2")
    _require_length(id_ed, 32, "Ed25519-идентификатор EXTEND2")
    spec = [(0x00, ip + struct.pack(">H", port)), (0x02, id_rsa), (0x03, id_ed)]
    return (bytes([len(spec)]) + b"".join(bytes([t, len(d)]) + d for t, d in spec)
            + create2_body(htype, hdata))
