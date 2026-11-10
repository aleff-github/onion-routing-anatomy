# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Приложение B: преобразование X25519 (Montgomery) в Ed25519 (Edwards).

Источник: dir-spec, "Converting a curve25519 public key to an ed25519 public key".
Используется для проверки поля ntor-onion-key-crosscert в описаниях ретрансляторов: это сертификат Ed25519,
подписанный ключом ntor ретранслятора, преобразованным в форму Эдвардса.
"""
from __future__ import annotations

import base64
import re

P = 2**255 - 19


def montgomery_to_edwards(u_bytes: bytes, sign: int) -> bytes:
    """Координата u (32 байта, младший байт первым) -> сжатый ключ Ed25519.

    y = (u - 1) / (u + 1) mod p; сжатая запись содержит y с младшим байтом первым,
    а старший бит последнего байта равен знаку координаты x.
    """
    if len(u_bytes) != 32:
        raise ValueError("открытый ключ ntor должен иметь длину ровно 32 байта")
    if sign not in (0, 1):
        raise ValueError("знаковый бит координаты Эдвардса должен быть 0 или 1")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    if (u + 1) % P == 0:
        raise ValueError("некорректная координата u: нет обратного знаменателя")
    y = (u - 1) * pow(u + 1, P - 2, P) % P
    compressed = bytearray(y.to_bytes(32, "little"))
    compressed[31] |= (sign & 1) << 7
    return bytes(compressed)


def _decode_ntor_key(value: str) -> bytes:
    """Строго декодировать открытый ключ ntor из base64."""
    result = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if len(result) != 32:
        raise ValueError("открытый ключ ntor должен иметь длину ровно 32 байта")
    return result


def verify_crosscert(ntor_onion_key_b64: str, sign: int, cert: bytes) -> bytes:
    """Проверить подпись сертификата преобразованным ключом ntor; вернуть
    сертифицированный ключ — основную идентичность Ed25519 ретранслятора.
    Полученный ключ требуется сверить с master-key-ed25519 в описании узла."""
    from .channel import decode_ed_certificate
    u = _decode_ntor_key(ntor_onion_key_b64)
    c = decode_ed_certificate(cert)
    if c.kind != 0x0A or c.key_type != 1:
        raise ValueError("сертификат ntor должен иметь тип 0x0A и ключ Ed25519")
    if c.signing_key is not None:
        raise ValueError("сертификат ntor не должен включать расширение с ключом подписи")
    c.verify_signature(montgomery_to_edwards(u, sign))
    if c.expired():
        raise ValueError("срок действия сертификата ntor истёк")
    return c.certified_key


def _pem(text: str) -> bytes:
    lines = [r.strip() for r in text.splitlines() if r.strip() and not r.startswith("-----")]
    return base64.b64decode("".join(lines), validate=True)


if __name__ == "__main__":
    import sys
    descriptor = open(sys.argv[1], encoding="utf-8").read()
    name = sys.argv[2]
    entry = [x for x in re.split(r"(?m)^router ", descriptor) if x.startswith(name + " ")][-1]
    ntor = entry.split("\nntor-onion-key ")[1].split()[0]
    after = entry.split("\nntor-onion-key-crosscert ")[1]
    sign = int(after.split()[0])
    pem = after.split("-----BEGIN ED25519 CERT-----", 1)[1].split("-----END ED25519 CERT-----")[0]
    identity = verify_crosscert(ntor, sign, _pem(pem))
    print(f"{name}: ntor-onion-key {ntor}")
    print(f"  ключ Эдвардса (знак {sign}): {montgomery_to_edwards(_decode_ntor_key(ntor), sign).hex()}")
    print(f"  перекрёстный сертификат действителен; подтверждённая идентичность: {base64.b64encode(identity).decode().rstrip('=')}")
