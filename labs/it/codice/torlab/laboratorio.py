# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Funzioni per consultare i nodi della rete Tor privata dei laboratori del libro."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

NODI = Path(__file__).resolve().parents[2] / "laboratorio" / "net" / "nodes"


def _b64(s: str) -> bytes:
    if not s or not s.strip():
        raise ValueError("valore base64 vuoto")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def _microdescriptors(text: str):
    """Scorre i microdescrittori delimitati dalla riga onion-key, anche senza annotazioni."""
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
                raise ValueError("campo Ed25519 duplicato nel microdescrittore")
            fields["id_ed"] = line[len("id ed25519 "):].strip()
        elif line.startswith("ntor-onion-key "):
            if "ntor" in fields:
                raise ValueError("chiave ntor duplicata nel microdescrittore")
            fields["ntor"] = line[len("ntor-onion-key "):].strip()
    if fields is not None:
        yield fields


@dataclass
class InfoRelay:
    nome: str
    porta: int
    id_rsa: bytes      # impronta SHA-1 dell'identità RSA (20 byte)
    id_ed: bytes       # chiave di identità Ed25519 (32 byte)
    ntor: bytes        # chiave pubblica ntor (32 byte)


def cartella_client() -> str:
    """Restituisce il primo nodo client della rete (008c in libro; 010c in libro-bridge)."""
    clients = sorted(p.name for p in NODI.iterdir()
                     if p.is_dir() and re.fullmatch(r"[0-9]{3}c", p.name))
    if not clients:
        raise LookupError("nessun nodo client nella rete del laboratorio")
    return clients[0]


def relay(nome: str, client: str | None = None) -> InfoRelay:
    """Legge le identità locali del relay e la sua chiave ntor dalla cache del client."""
    if not re.fullmatch(r"[0-9]{3}[a-z]", nome):
        raise ValueError("nome del nodo non valido")
    client = client or cartella_client()
    if not re.fullmatch(r"[0-9]{3}c", client):
        raise ValueError("identificativo client non valido")
    d = NODI / nome
    rsa_words = (d / "fingerprint").read_text(encoding="utf-8").split()
    if len(rsa_words) < 2:
        raise ValueError("file fingerprint incompleto")
    id_rsa = bytes.fromhex(rsa_words[1])
    if len(id_rsa) != 20:
        raise ValueError("impronta RSA non lunga 20 byte")
    ed_words = (d / "fingerprint-ed25519").read_text(encoding="utf-8").split()
    if len(ed_words) < 2:
        raise ValueError("file fingerprint-ed25519 incompleto")
    id_ed = _b64(ed_words[1])
    if len(id_ed) != 32:
        raise ValueError("identità Ed25519 non lunga 32 byte")
    porta = 5100 + int(nome[:3])

    cache = NODI / client / "cached-microdescs.new"
    if not cache.is_file():
        cache = NODI / client / "cached-microdescs"
    for fields in _microdescriptors(cache.read_text(encoding="utf-8")):
        identity = fields.get("id_ed")
        if identity is None or _b64(identity) != id_ed:
            continue
        key = fields.get("ntor")
        if key is None:
            raise ValueError(f"chiave ntor assente per {nome}")
        ntor = _b64(key)
        if len(ntor) != 32:
            raise ValueError(f"chiave ntor non lunga 32 byte per {nome}")
        return InfoRelay(nome, porta, id_rsa, id_ed, ntor)
    raise LookupError(f"nessun microdescrittore per {nome}")
