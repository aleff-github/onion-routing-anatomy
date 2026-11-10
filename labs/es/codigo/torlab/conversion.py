# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Apéndice B: convertir una clave X25519 (Montgomery) a Ed25519 (Edwards).

Referencia: dir-spec, conversión de claves públicas Curve25519 a Ed25519.
Permite verificar el campo ntor-onion-key-crosscert de descriptores:
certificado Ed25519 firmado con la clave ntor del repetidor convertida a Edwards.
"""
from __future__ import annotations

import base64
import re

P = 2**255 - 19


def montgomery_to_edwards(u_bytes: bytes, sign: int) -> bytes:
    """Coordenada u (32 bytes little-endian) -> clave Ed25519 comprimida.

    y = (u - 1) / (u + 1) mod p. La clave comprimida representa y en
    little-endian con el bit más alto del último byte igual al signo de x.
    """
    if len(u_bytes) != 32:
        raise ValueError("la clave pública ntor debe tener exactamente 32 bytes")
    if sign not in (0, 1):
        raise ValueError("el bit de signo de Edwards debe ser 0 o 1")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    if (u + 1) % P == 0:
        raise ValueError("coordenada u inválida: el denominador no es invertible")
    y = (u - 1) * pow(u + 1, P - 2, P) % P
    compressed = bytearray(y.to_bytes(32, "little"))
    compressed[31] |= (sign & 1) << 7
    return bytes(compressed)


def _decode_ntor_key(value: str) -> bytes:
    """Descodifica estricta de la clave pública ntor en base64."""
    result = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if len(result) != 32:
        raise ValueError("la clave pública ntor debe tener exactamente 32 bytes")
    return result


def verify_crosscert(ntor_onion_key_b64: str, sign: int, cert: bytes) -> bytes:
    """Verifica la firma del certificado con la clave ntor convertida y devuelve
    la clave certificada (identidad Ed25519 principal del repetidor).
    Hay que compararla con master-key-ed25519 del descriptor."""
    from .channel import decode_ed_certificate
    u = _decode_ntor_key(ntor_onion_key_b64)
    c = decode_ed_certificate(cert)
    if c.kind != 0x0A or c.key_type != 1:
        raise ValueError("el certificado ntor debe ser de tipo 0x0A y certificar una clave Ed25519")
    if c.signing_key is not None:
        raise ValueError("el crosscert ntor no debe incluir una extensión de clave firmante")
    c.verify_signature(montgomery_to_edwards(u, sign))
    if c.expired():
        raise ValueError("el crosscert ntor ha caducado")
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
    print(f"  Clave Edwards (signo {sign}): {montgomery_to_edwards(_decode_ntor_key(ntor), sign).hex()}")
    print(f"  crosscert válido; identidad certificada: {base64.b64encode(identity).decode().rstrip('=')}")
