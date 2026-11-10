# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""读取本书私有 Tor 实验网络中继身份与密钥的辅助函数。"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

NODES = Path(__file__).resolve().parents[2] / "实验室" / "net" / "nodes"


def _b64(s: str) -> bytes:
    if not s or not s.strip():
        raise ValueError("base64 值不能为空")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def _microdescriptors(text: str):
    """以 onion-key 起始行划分微描述符，无论是否包含注释。"""
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
                raise ValueError("微描述符包含重复的 Ed25519 字段")
            fields["id_ed"] = line[len("id ed25519 "):].strip()
        elif line.startswith("ntor-onion-key "):
            if "ntor" in fields:
                raise ValueError("微描述符包含重复的 ntor 公钥")
            fields["ntor"] = line[len("ntor-onion-key "):].strip()
    if fields is not None:
        yield fields


@dataclass
class RelayInfo:
    name: str
    port: int
    id_rsa: bytes      # RSA 身份的 SHA-1 指纹（20 字节）
    id_ed: bytes       # Ed25519 身份公钥（32 字节）
    ntor: bytes        # ntor 公钥（32 字节）


def client_directory() -> str:
    """返回首个客户端节点（book 中为 008c；book-bridge 中为 010c）。"""
    clients = sorted(p.name for p in NODES.iterdir()
                     if p.is_dir() and re.fullmatch(r"[0-9]{3}c", p.name))
    if not clients:
        raise LookupError("实验网络中没有客户端节点")
    return clients[0]


def relay(name: str, client: str | None = None) -> RelayInfo:
    """读取中继本地身份，并从客户端缓存读取该中继的 ntor 公钥。"""
    if not re.fullmatch(r"[0-9]{3}[a-z]", name):
        raise ValueError("节点名称无效")
    client = client or client_directory()
    if not re.fullmatch(r"[0-9]{3}c", client):
        raise ValueError("客户端标识无效")
    d = NODES / name
    rsa_words = (d / "fingerprint").read_text(encoding="utf-8").split()
    if len(rsa_words) < 2:
        raise ValueError("fingerprint 文件不完整")
    id_rsa = bytes.fromhex(rsa_words[1])
    if len(id_rsa) != 20:
        raise ValueError("RSA 指纹必须为 20 字节")
    ed_words = (d / "fingerprint-ed25519").read_text(encoding="utf-8").split()
    if len(ed_words) < 2:
        raise ValueError("fingerprint-ed25519 文件不完整")
    id_ed = _b64(ed_words[1])
    if len(id_ed) != 32:
        raise ValueError("Ed25519 身份必须为 32 字节")
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
            raise ValueError(f"缺少 ntor 公钥： {name}")
        ntor = _b64(key)
        if len(ntor) != 32:
            raise ValueError(f"ntor 公钥长度必须为 32 字节： {name}")
        return RelayInfo(name, port, id_rsa, id_ed, ntor)
    raise LookupError(f"找不到微描述符： {name}")
