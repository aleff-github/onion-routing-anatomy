# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 6：下载并验证网络共识。

规范依据：dir-spec 中 Vote and consensus status document formats、
Signing documents、General-use HTTP URLs 与 Creating key certificates。
本模块仅供本书私有实验网络使用。
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .cells import RelayCommand, RelayMessage
from .circuit import Circuit, CircuitError
from .stream import Stream


# --- 使用 BEGIN_DIR 下载目录文档 ------------------------------------------

def download(circ: Circuit, path: str, stream_id: int) -> bytes:
    """通过 BEGIN_DIR 流向末端中继的目录服务发出 HTTP/1.0 GET 请求。"""
    if any(ch in path for ch in ("\r", "\n", "\x00")):
        raise CircuitError("HTTP 路径含有控制字符")
    s = Stream(circ, stream_id)
    circ.send(RelayMessage(RelayCommand.BEGIN_DIR, stream_id, b""))
    _, msg = s._next()
    if msg.command != RelayCommand.CONNECTED:
        raise CircuitError(f"BEGIN_DIR 请求被拒绝：{msg.command}")
    s.send(f"GET {path} HTTP/1.0\r\n\r\n".encode())
    response = s.receive_all()
    header, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        raise CircuitError("HTTP 响应缺少头部与正文分隔符")
    state = header.split(b"\r\n")[0]
    if not re.fullmatch(rb"HTTP/1\.[01] 200(?:[ \t].*)?", state):
        raise CircuitError(f"{path}: {state.decode('utf-8', errors='replace')}")
    return body


# --- 网络文档：条目与嵌入对象 ------------------------------------

@dataclass
class Item:
    keyword: str
    arguments: list[str]
    object_text: bytes | None = None      # -----BEGIN ...----- 区块的内容


def items(text: str) -> list[Item]:
    """将 netdoc 格式文档拆分为条目（dir-spec，netdoc）。"""
    output, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line:
            continue
        keyword, *arguments = line.split(" ")
        object_text = None
        if i < len(lines) and lines[i].startswith("-----BEGIN "):
            label = lines[i][len("-----BEGIN "):-5]
            expected_end = f"-----END {label}-----"
            j = i + 1
            while j < len(lines) and lines[j] != expected_end:
                if lines[j].startswith("-----END "):
                    raise ValueError("PEM 区块未闭合或结束标记不匹配")
                j += 1
            if j == len(lines):
                raise ValueError("PEM 区块未闭合或结束标记不匹配")
            object_text = "\n".join(lines[i:j + 1]).encode()
            i = j + 1
        output.append(Item(keyword, arguments, object_text))
    return output


def _pem_body(object_text: bytes) -> bytes:
    if not object_text or len(object_text.split(b"\n")) < 3:
        raise ValueError("PEM 区块缺失或格式错误")
    return base64.b64decode(b"".join(object_text.split(b"\n")[1:-1]), validate=True)


def _b64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


# --- 网络共识 -----------------------------------------------------------------

@dataclass
class RelayEntry:
    name: str
    id_rsa: bytes
    ip: str
    orport: int
    flag: set[str] = field(default_factory=set)
    bandwidth: int | None = None
    policy: str = ""
    microdesc: bytes | None = None
    version: str = ""
    protocols: str = ""


@dataclass
class Signature:
    algorithm: str
    identity: str          # 权威节点身份指纹（十六进制）
    signing_key: str      # 签名密钥指纹（十六进制）
    signature: bytes


@dataclass
class Consensus:
    text: str
    header: dict[str, list[str]]
    relay: list[RelayEntry]
    signatures: list[Signature]
    parameters: dict[str, int]
    weights: dict[str, int]


def parse_consensus(text: str) -> Consensus:
    header, relay, signatures = {}, [], []
    parameters, weights = {}, {}
    current = None
    for it in items(text):
        if it.keyword == "r":
            current = RelayEntry(it.arguments[0], _b64(it.arguments[1]), it.arguments[-3],
                                 int(it.arguments[-2]))
            relay.append(current)
        elif it.keyword == "s" and current:
            current.flag = set(it.arguments)
        elif it.keyword == "w" and current:
            fields = dict(a.split("=") for a in it.arguments)
            current.bandwidth = int(fields.get("Bandwidth", 0))
        elif it.keyword == "p" and current:
            current.policy = " ".join(it.arguments)
        elif it.keyword == "m" and current:
            current.microdesc = _b64(it.arguments[0])
        elif it.keyword == "v" and current:
            current.version = " ".join(it.arguments)
        elif it.keyword == "pr" and current:
            current.protocols = " ".join(it.arguments)
        elif it.keyword == "params":
            parameters = {k: int(v) for k, v in (a.split("=") for a in it.arguments)}
        elif it.keyword == "bandwidth-weights":
            weights = {k: int(v) for k, v in (a.split("=") for a in it.arguments)}
        elif it.keyword == "directory-signature":
            alg = it.arguments[0] if len(it.arguments) == 3 else "sha1"
            signatures.append(Signature(alg, it.arguments[-2], it.arguments[-1], _pem_body(it.object_text)))
        elif current is None:
            header[it.keyword] = it.arguments
    return Consensus(text, header, relay, signatures, parameters, weights)


# --- 权威节点证书与签名验证 -------------------------------

@dataclass
class AuthorityCertificate:
    identity_fingerprint: str       # 大写十六进制
    signing_key: rsa.RSAPublicKey
    signing_key_fingerprint: str


def parse_certificates(text: str) -> list[AuthorityCertificate]:
    certificates, current_cert = [], {}
    for it in items(text):
        if it.keyword == "fingerprint":
            current_cert["id"] = it.arguments[0].upper()
        elif it.keyword == "dir-signing-key":
            der = _pem_body(it.object_text)
            current_cert["key"] = _load_rsa_pkcs1(it.object_text)
            current_cert["key_fingerprint"] = hashlib.sha1(der).hexdigest().upper()
        elif it.keyword == "dir-key-certification" and current_cert:
            certificates.append(AuthorityCertificate(current_cert["id"], current_cert["key"],
                                                   current_cert["key_fingerprint"]))
            current_cert = {}
    return certificates


def _load_rsa_pkcs1(object_text: bytes) -> rsa.RSAPublicKey:
    # "-----BEGIN RSA PUBLIC KEY-----" 使用 PKCS#1 格式，cryptography 能以 PEM 方式读取.
    return load_pem_public_key(object_text)


def signed_text(text: str) -> bytes:
    """共识签名覆盖的区域：从 network-status-version 开始，
    直到 directory-signature 关键字之后的空格（dir-spec，directory-signature）。

    CollecTor 下载文件可能以 @type 注释开头；它不属于已签名文档，
    计算摘要前必须去除。
    """
    start = re.search(r"(?m)^network-status-version ", text)
    if start is None:
        raise ValueError("network-status-version missing")
    end = re.search(r"(?m)^directory-signature ", text[start.start():])
    if end is None:
        raise ValueError("directory-signature missing")
    return text[start.start():start.start() + end.end()].encode()


def verify_signature(consensus: Consensus, signature: Signature, cert: AuthorityCertificate) -> bool:
    """签名采用不包含算法标识符的 RSA PKCS#1 v1.5 摘要格式；
    从签名中恢复摘要，再与本地计算值比较。"""
    if signature.algorithm not in ("sha1", "sha256"):
        return False
    h = hashlib.sha256 if signature.algorithm == "sha256" else hashlib.sha1
    expected = h(signed_text(consensus.text)).digest()
    try:
        recovered = cert.signing_key.recover_data_from_signature(
            signature.signature, padding.PKCS1v15(), None)
    except Exception:
        return False
    return recovered == expected


def verify_consensus(consensus: Consensus, certificates: list[AuthorityCertificate],
                      authority_count: int) -> tuple[int, int, list[str]]:
    """统计至少有一个有效签名的权威节点，返回（有效数量、所需数量、详情）。
    注意：这里只统计数学上有效的 RSA 签名；并未认证权威节点证书、检查有效期或绑定可信权威节点身份。"""
    by_key = {c.signing_key_fingerprint: c for c in certificates}
    valid_count, details = set(), []
    for f in consensus.signatures:
        cert = by_key.get(f.signing_key.upper())
        result = bool(cert and cert.identity_fingerprint == f.identity.upper()
                     and verify_signature(consensus, f, cert))
        details.append(f"{f.identity[:8]} {f.algorithm}: {'valid' if result else 'INVALID'}")
        if result:
            valid_count.add(f.identity.upper())
    return len(valid_count), authority_count // 2 + 1, details


# --- 微描述符 ---------------------------------------------------------------

def parse_microdescriptors(text: str) -> dict[bytes, dict]:
    """返回 {微描述符 SHA-256：字段}；每份微描述符都以 onion-key 开始。"""
    result = {}
    for m in re.finditer(r"(?m)^onion-key\n.*?(?=^onion-key\n|^@last-listed |\Z)", text, re.S):
        block = m.group().rstrip("\n") + "\n"
        fields = {}
        for it in items(block):
            if it.keyword in ("ntor-onion-key",):
                fields["ntor"] = _b64(it.arguments[0])
            elif it.keyword == "id" and it.arguments[0] == "ed25519":
                fields["ed25519"] = _b64(it.arguments[1])
            elif it.keyword == "family":
                fields["family"] = it.arguments
            elif it.keyword == "p":
                fields["policy"] = " ".join(it.arguments)
        result[hashlib.sha256(block.encode()).digest()] = fields
    return result
