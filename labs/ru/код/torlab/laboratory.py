# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Вспомогательные функции для чтения идентификаторов и ключей узлов частной лабораторной сети Tor."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

NODES = Path(__file__).resolve().parents[2] / "лаборатория" / "net" / "nodes"


def _b64(s: str) -> bytes:
    if not s or not s.strip():
        raise ValueError("пустое значение base64")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def _microdescriptors(text: str):
    """Перебрать микродескрипторы по начальной строке onion-key, с аннотациями или без."""
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
                raise ValueError("повторное поле Ed25519 в микродескрипторе")
            fields["id_ed"] = line[len("id ed25519 "):].strip()
        elif line.startswith("ntor-onion-key "):
            if "ntor" in fields:
                raise ValueError("повторный ключ ntor в микродескрипторе")
            fields["ntor"] = line[len("ntor-onion-key "):].strip()
    if fields is not None:
        yield fields


@dataclass
class RelayInfo:
    name: str
    port: int
    id_rsa: bytes      # SHA-1-отпечаток идентификатора RSA (20 байт)
    id_ed: bytes       # открытый ключ идентификатора Ed25519 (32 байта)
    ntor: bytes        # открытый ключ ntor (32 байта)


def client_directory() -> str:
    """Вернуть первый клиентский узел (008c в book; 010c в book-bridge)."""
    clients = sorted(p.name for p in NODES.iterdir()
                     if p.is_dir() and re.fullmatch(r"[0-9]{3}c", p.name))
    if not clients:
        raise LookupError("в лабораторной сети нет клиентского узла")
    return clients[0]


def relay(name: str, client: str | None = None) -> RelayInfo:
    """Прочитать локальные идентификаторы ретранслятора и его ключ ntor из кэша клиента."""
    if not re.fullmatch(r"[0-9]{3}[a-z]", name):
        raise ValueError("недопустимое имя узла")
    client = client or client_directory()
    if not re.fullmatch(r"[0-9]{3}c", client):
        raise ValueError("недопустимый идентификатор клиента")
    d = NODES / name
    rsa_words = (d / "fingerprint").read_text(encoding="utf-8").split()
    if len(rsa_words) < 2:
        raise ValueError("неполный файл fingerprint")
    id_rsa = bytes.fromhex(rsa_words[1])
    if len(id_rsa) != 20:
        raise ValueError("RSA-отпечаток должен содержать 20 байт")
    ed_words = (d / "fingerprint-ed25519").read_text(encoding="utf-8").split()
    if len(ed_words) < 2:
        raise ValueError("неполный файл fingerprint-ed25519")
    id_ed = _b64(ed_words[1])
    if len(id_ed) != 32:
        raise ValueError("идентификатор Ed25519 должен содержать 32 байта")
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
            raise ValueError(f"отсутствует ключ ntor для {name}")
        ntor = _b64(key)
        if len(ntor) != 32:
            raise ValueError(f"ключ ntor должен содержать 32 байта для {name}")
        return RelayInfo(name, port, id_rsa, id_ed, ntor)
    raise LookupError(f"микродескриптор не найден для {name}")
