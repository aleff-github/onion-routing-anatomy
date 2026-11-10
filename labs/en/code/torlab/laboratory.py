# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Helpers for reading relay identities and keys in the book's private Tor laboratory network."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

NODES = Path(__file__).resolve().parents[2] / "lab" / "net" / "nodes"


def _b64(s: str) -> bytes:
    if not s or not s.strip():
        raise ValueError("empty base64 value")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def _microdescriptors(text: str):
    """Iterate over microdescriptors separated by onion-key, with or without annotations."""
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
                raise ValueError("duplicate Ed25519 field in microdescriptor")
            fields["id_ed"] = line[len("id ed25519 "):].strip()
        elif line.startswith("ntor-onion-key "):
            if "ntor" in fields:
                raise ValueError("duplicate ntor key in microdescriptor")
            fields["ntor"] = line[len("ntor-onion-key "):].strip()
    if fields is not None:
        yield fields


@dataclass
class RelayInfo:
    name: str
    port: int
    id_rsa: bytes      # SHA-1 fingerprint of the RSA identity (20 bytes)
    id_ed: bytes       # Ed25519 identity public key (32 bytes)
    ntor: bytes        # ntor public key (32 bytes)


def client_directory() -> str:
    """Return the first client node (008c in book; 010c in book-bridge)."""
    clients = sorted(p.name for p in NODES.iterdir()
                     if p.is_dir() and re.fullmatch(r"[0-9]{3}c", p.name))
    if not clients:
        raise LookupError("no client node found in the laboratory network")
    return clients[0]


def relay(name: str, client: str | None = None) -> RelayInfo:
    """Read local relay identities and its ntor key from the client's cache."""
    if not re.fullmatch(r"[0-9]{3}[a-z]", name):
        raise ValueError("invalid node name")
    client = client or client_directory()
    if not re.fullmatch(r"[0-9]{3}c", client):
        raise ValueError("invalid client identifier")
    d = NODES / name
    rsa_words = (d / "fingerprint").read_text(encoding="utf-8").split()
    if len(rsa_words) < 2:
        raise ValueError("incomplete fingerprint file")
    id_rsa = bytes.fromhex(rsa_words[1])
    if len(id_rsa) != 20:
        raise ValueError("RSA fingerprint must be 20 bytes")
    ed_words = (d / "fingerprint-ed25519").read_text(encoding="utf-8").split()
    if len(ed_words) < 2:
        raise ValueError("incomplete fingerprint-ed25519 file")
    id_ed = _b64(ed_words[1])
    if len(id_ed) != 32:
        raise ValueError("Ed25519 identity must be 32 bytes")
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
            raise ValueError(f"missing ntor key for {name}")
        ntor = _b64(key)
        if len(ntor) != 32:
            raise ValueError(f"ntor key must be 32 bytes for {name}")
        return RelayInfo(name, port, id_rsa, id_ed, ntor)
    raise LookupError(f"no microdescriptor for {name}")
