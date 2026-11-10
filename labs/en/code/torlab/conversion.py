# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Appendix B: convert an X25519 (Montgomery) key to an Ed25519 (Edwards) key.

Reference: dir-spec, "Converting a curve25519 public key to an ed25519 public key".
Used to verify the ntor-onion-key-crosscert field in descriptors: an Ed25519 certificate
signed with the relay's ntor key, converted to Edwards form.
"""
from __future__ import annotations

import base64
import re

P = 2**255 - 19


def montgomery_to_edwards(u_bytes: bytes, sign: int) -> bytes:
    """Montgomery u coordinate (32 little-endian bytes) -> compressed Ed25519 key.

    y = (u - 1) / (u + 1) mod p; the compressed key encodes y in little-endian
    with the x-coordinate sign in the high bit of the last byte.
    """
    if len(u_bytes) != 32:
        raise ValueError("the ntor public key must be exactly 32 bytes")
    if sign not in (0, 1):
        raise ValueError("the Edwards sign bit must be 0 or 1")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    if (u + 1) % P == 0:
        raise ValueError("invalid u coordinate: denominator has no inverse")
    y = (u - 1) * pow(u + 1, P - 2, P) % P
    compressed = bytearray(y.to_bytes(32, "little"))
    compressed[31] |= (sign & 1) << 7
    return bytes(compressed)


def _decode_ntor_key(value: str) -> bytes:
    """Strict base64 decoding of the ntor public key."""
    result = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if len(result) != 32:
        raise ValueError("the ntor public key must be exactly 32 bytes")
    return result


def verify_crosscert(ntor_onion_key_b64: str, sign: int, cert: bytes) -> bytes:
    """Verify the certificate signature with the converted ntor key; return the
    certified key (the relay's primary Ed25519 identity).
    The caller must compare it with the descriptor's master-key-ed25519 field."""
    from .channel import decode_ed_certificate
    u = _decode_ntor_key(ntor_onion_key_b64)
    c = decode_ed_certificate(cert)
    if c.kind != 0x0A or c.key_type != 1:
        raise ValueError("ntor crosscert must have type 0x0A and an Ed25519 certified key")
    if c.signing_key is not None:
        raise ValueError("ntor crosscert must not include a signing-key extension")
    c.verify_signature(montgomery_to_edwards(u, sign))
    if c.expired():
        raise ValueError("ntor crosscert has expired")
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
    print(f"  Edwards key (sign {sign}): {montgomery_to_edwards(_decode_ntor_key(ntor), sign).hex()}")
    print(f"  valid crosscert; certified identity: {base64.b64encode(identity).decode().rstrip('=')}")
