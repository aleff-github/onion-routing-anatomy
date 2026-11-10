# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Funciones para leer identidades y claves de relés de la red Tor privada del laboratorio."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

NODES = Path(__file__).resolve().parents[2] / "laboratorio" / "net" / "nodes"


def _b64(s: str) -> bytes:
    if not s or not s.strip():
        raise ValueError("valor base64 vacío")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def _microdescriptors(text: str):
    """Recorre microdescriptores separados por onion-key, con o sin anotaciones."""
    fields = None
    for line in text.splitlines():
        if line == "onion-key":
            if fields is not None:
                yield fields
            fields = {}
            continue
        if fields is None:
            continue
        if line.startswith("id ed25519 "):
            if "id_ed" in fields:
                raise ValueError("campo Ed25519 duplicado en el microdescriptor")
            fields["id_ed"] = line[len("id ed25519 "):].strip()
        elif line.startswith("ntor-onion-key "):
            if "ntor" in fields:
                raise ValueError("clave ntor duplicada en el microdescriptor")
            fields["ntor"] = line[len("ntor-onion-key "):].strip()
    if fields is not None:
        yield fields


@dataclass
class RelayInfo:
    name: str
    port: int
    id_rsa: bytes      # huella SHA-1 de la identidad RSA (20 bytes)
    id_ed: bytes       # clave pública de identidad Ed25519 (32 bytes)
    ntor: bytes        # clave pública ntor (32 bytes)


def client_directory() -> str:
    """Devuelve el primer cliente (008c en book; 010c en book-bridge)."""
    clients = sorted(p.name for p in NODES.iterdir()
                     if p.is_dir() and re.fullmatch(r"[0-9]{3}c", p.name))
    if not clients:
        raise LookupError("no se encontró un cliente en la red del laboratorio")
    return clients[0]


def relay(name: str, client: str | None = None) -> RelayInfo:
    """Lee las identidades locales del relé y su clave ntor de la caché del cliente."""
    if not re.fullmatch(r"[0-9]{3}[a-z]", name):
        raise ValueError("nombre de nodo no válido")
    client = client or client_directory()
    if not re.fullmatch(r"[0-9]{3}c", client):
        raise ValueError("identificador de cliente no válido")
    d = NODES / name
    rsa_words = (d / "fingerprint").read_text(encoding="utf-8").split()
    if len(rsa_words) < 2:
        raise ValueError("archivo fingerprint incompleto")
    id_rsa = bytes.fromhex(rsa_words[1])
    if len(id_rsa) != 20:
        raise ValueError("la huella RSA debe tener 20 bytes")
    ed_words = (d / "fingerprint-ed25519").read_text(encoding="utf-8").split()
    if len(ed_words) < 2:
        raise ValueError("archivo fingerprint-ed25519 incompleto")
    id_ed = _b64(ed_words[1])
    if len(id_ed) != 32:
        raise ValueError("la identidad Ed25519 debe tener 32 bytes")
    port = 5100 + int(name[:3])

    cache = NODES / client / "cached-microdescs.new"
    if not cache.is_file():
        cache = NODES / client / "cached-microdescs"
    for fields in _microdescriptors(cache.read_text(encoding="utf-8")):
        identity = fields.get("id_ed")
        if identity is None or _b64(identity) != id_ed:
            continue
        key = fields.get("ntor")
        if key is None:
            raise ValueError(f"falta la clave ntor para {name}")
        ntor = _b64(key)
        if len(ntor) != 32:
            raise ValueError(f"la clave ntor debe tener 32 bytes para {name}")
        return RelayInfo(name, port, id_rsa, id_ed, ntor)
    raise LookupError(f"no hay microdescriptor para {name}")
