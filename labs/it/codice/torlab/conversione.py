# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Appendice B: da una chiave X25519 (Montgomery) a una chiave Ed25519 (Edwards).

Riferimento: dir-spec, "Converting a curve25519 public key to an ed25519 public key".
Serve a verificare il campo ntor-onion-key-crosscert dei descrittori: un certificato Ed25519
firmato con la chiave ntor del relay, convertita nella forma di Edwards.
"""
from __future__ import annotations

import base64
import binascii
import re

P = 2**255 - 19


def montgomery_a_edwards(u_bytes: bytes, segno: int) -> bytes:
    """Coordinata u (32 byte little-endian) -> chiave Ed25519 compressa.

    y = (u - 1) / (u + 1) mod p; la chiave compressa è y in little-endian con il bit
    più alto dell'ultimo byte uguale al segno della coordinata x.
    """
    if len(u_bytes) != 32:
        raise ValueError("la chiave ntor deve contenere esattamente 32 byte")
    if segno not in (0, 1):
        raise ValueError("il bit di segno deve essere 0 oppure 1")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    if (u + 1) % P == 0:
        raise ValueError("coordinata u non convertibile: denominatore nullo")
    y = (u - 1) * pow(u + 1, P - 2, P) % P
    compressa = bytearray(y.to_bytes(32, "little"))
    compressa[31] |= (segno & 1) << 7
    return bytes(compressa)


def _decode_ntor_key(value: str) -> bytes:
    """Decodifica rigorosa della chiave ntor in base64."""
    result = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if len(result) != 32:
        raise ValueError("la chiave ntor deve contenere esattamente 32 byte")
    return result


def verifica_crosscert(ntor_onion_key_b64: str, segno: int, cert: bytes) -> bytes:
    """Verifica la firma del certificato con la chiave ntor convertita; restituisce la chiave
    certificata (l'identità Ed25519 principale del relay).
    Chi usa il risultato deve confrontarlo con master-key-ed25519 del descrittore."""
    from .canale import decodifica_cert_ed
    u = _decode_ntor_key(ntor_onion_key_b64)
    c = decodifica_cert_ed(cert)
    if c.tipo != 0x0A or c.tipo_chiave != 1:
        raise ValueError("il certificato ntor deve avere tipo 0x0A e chiave Ed25519")
    if c.chiave_firmataria is not None:
        raise ValueError("il crosscert ntor non deve includere una chiave firmataria aggiuntiva")
    c.verifica_firma(montgomery_a_edwards(u, segno))
    if c.scaduto():
        raise ValueError("crosscert ntor scaduto")
    return c.chiave_certificata


def verifica_identita_descrittore(voce: str, identita: bytes) -> None:
    """Confronta l'identità certificata ntor con master-key-ed25519.

    Non sostituisce il controllo delle altre firme del descrittore.
    """
    if len(identita) != 32:
        raise ValueError("l'identità certificata deve avere 32 byte")
    # Contare prima tutte le dichiarazioni, anche quelle con Base64 malformato.
    # Altrimenti un secondo campo non valido potrebbe essere ignorato.
    righe = [
        line for line in voce.splitlines()
        if re.match(r"^master-key-ed25519(?:[ \t]|$)", line)
    ]
    if len(righe) != 1:
        raise ValueError("master-key-ed25519 assente o duplicata nel descrittore")
    campo = re.fullmatch(r"master-key-ed25519[ \t]+([A-Za-z0-9+/=]+)[ \t]*", righe[0])
    if campo is None:
        raise ValueError("master-key-ed25519 non valida nel descrittore")
    try:
        dichiarata = _decode_ntor_key(campo.group(1))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("master-key-ed25519 non valida nel descrittore") from exc
    if identita != dichiarata:
        raise ValueError("l'identità del crosscert non coincide con master-key-ed25519")


def _pem(testo: str) -> bytes:
    righe = [r.strip() for r in testo.splitlines() if r.strip() and not r.startswith("-----")]
    return base64.b64decode("".join(righe), validate=True)


if __name__ == "__main__":
    import sys
    descr = open(sys.argv[1], encoding="utf-8").read()
    nome = sys.argv[2]
    voce = [x for x in re.split(r"(?m)^router ", descr) if x.startswith(nome + " ")][-1]
    ntor = voce.split("\nntor-onion-key ")[1].split()[0]
    dopo = voce.split("\nntor-onion-key-crosscert ")[1]
    segno = int(dopo.split()[0])
    pem = dopo.split("-----BEGIN ED25519 CERT-----", 1)[1].split("-----END ED25519 CERT-----")[0]
    identita = verifica_crosscert(ntor, segno, _pem(pem))
    verifica_identita_descrittore(voce, identita)
    print(f"{nome}: ntor-onion-key {ntor}")
    print(f"  chiave Edwards (segno {segno}): {montgomery_a_edwards(_decode_ntor_key(ntor), segno).hex()}")
    print(f"  crosscert valido; identità certificata: {base64.b64encode(identita).decode().rstrip('=')}")
