# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 1：建立到中继的通道并验证其身份。

规范依据：tor-spec 的 Channels、Negotiating and initializing channels，
以及 cert-spec 的 Tor Ed25519 Certificates。与正式 Tor 客户端相同，
本教学客户端不向中继认证自己的身份，只发送 VERSIONS 与 NETINFO。
仅允许在本书私有实验网络中使用。
"""
from __future__ import annotations

import base64
import hashlib
import os
import ipaddress
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .cells import Cell, CellCommand, CellError, versions_cell, encode, decode, negotiate_version

SUPPORTED_VERSIONS = [4, 5]      # 与 Arti 一致：不使用链路协议版本 3

# CERTS cell 的证书类型（cert-spec，Certificate types）。
CERT_RSA_ID_X509 = 0x02
CERT_IDENTITY_V_SIGNING = 0x04
CERT_SIGNING_V_TLS_CERT = 0x05
CERT_RSA_ID_V_IDENTITY = 0x07
EXT_SIGNED_WITH_ED25519_KEY = 0x04


class ChannelError(Exception):
    """通道握手失败。"""


 # --- Tor Ed25519 certificates ------------------------------------------------

@dataclass
class EdCertificate:
    kind: int
    expiration_hours: int            # 自 Unix 纪元以来的小时数
    key_type: int
    certified_key: bytes    # 32 字节
    extensions: dict[int, tuple[int, bytes]]   # 类型 ->（标志，数据）
    signed_data: bytes               # 签名覆盖的字节
    signature: bytes

    @property
    def signing_key(self) -> bytes | None:
        """如果存在 signed-with-ed25519-key 扩展，则返回其中的密钥。"""
        est = self.extensions.get(EXT_SIGNED_WITH_ED25519_KEY)
        return est[1] if est else None

    def expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.expiration_hours * 3600 < now

    def verify_signature(self, public_key: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(self.signature, self.signed_data)
        except InvalidSignature:
            raise ChannelError(f"类型 {self.kind} 的证书签名无效（signature）") from None


def decode_ed_certificate(data: bytes) -> EdCertificate:
    """解析 Tor Ed25519 证书（cert-spec，ed-certs）。"""
    if len(data) < 40 + 64 or data[0] != 1:
        raise ChannelError("Ed25519 证书格式错误或版本不受支持")
    _, kind, expiration, key_type = struct.unpack(">BBIB", data[:7])
    key = data[7:39]
    extension_count = data[39]
    pos, extensions = 40, {}
    for _ in range(extension_count):
        if pos + 4 > len(data) - 64:
            raise ChannelError("Ed25519 证书扩展头不完整")
        length, extension_type, flag = struct.unpack(">HBB", data[pos:pos + 4])
        if pos + 4 + length > len(data) - 64:
            raise ChannelError("CERTS 证书超出信元边界")
        body = data[pos + 4:pos + 4 + length]
        if len(body) != length:
            raise ChannelError("扩展长度超过证书边界")
        if extension_type != EXT_SIGNED_WITH_ED25519_KEY and flag & 1:
            # 拒绝携带 AFFECTS_VALIDATION 标志的未知扩展。
            raise ChannelError(f"未知扩展 {extension_type} 会影响有效性")
        if extension_type in extensions:
            raise ChannelError("Ed25519 证书扩展类型重复")
        if extension_type == EXT_SIGNED_WITH_ED25519_KEY and length != 32:
            raise ChannelError("Ed25519 签名公钥扩展长度无效")
        extensions[extension_type] = (flag, body)
        pos += 4 + length
    if len(data) != pos + 64:
        raise ChannelError("证书长度不一致")
    return EdCertificate(kind, expiration, key_type, key, extensions, data[:pos], data[pos:])


def decode_certs(body: bytes) -> dict[int, bytes]:
    """解析 CERTS 消息体，返回 {CertType: 原始证书}。"""
    if not body:
        raise ChannelError("CERTS 信元为空")
    n, pos, certificates = body[0], 1, {}
    for _ in range(n):
        if pos + 3 > len(body):
            raise ChannelError("CERTS 证书头不完整")
        kind, length = struct.unpack(">BH", body[pos:pos + 3])
        if pos + 3 + length > len(body):
            raise ChannelError("CERTS 证书超出信元边界")
        if kind in certificates:
            raise ChannelError(f"类型 {kind} 的证书出现多次")
        certificates[kind] = body[pos + 3:pos + 3 + length]
        pos += 3 + length
    return certificates


def verify_responder_identity(certificates: dict[int, bytes], cert_tls_der: bytes) -> bytes:
    """遵循规范 Authenticating the responder from its CERTS 中的验证规则。

    如果 Ed25519 身份 -> 签名密钥 -> TLS 证书的认证链合法，
    则返回 32 字节 KP_relayid_ed；否则抛出 ChannelError。
    """
    try:
        id_v_sign = decode_ed_certificate(certificates[CERT_IDENTITY_V_SIGNING])
        sign_v_tls = decode_ed_certificate(certificates[CERT_SIGNING_V_TLS_CERT])
    except KeyError as e:
        raise ChannelError(f"缺少类型 {e.args[0]} 的证书") from None

    if id_v_sign.kind != CERT_IDENTITY_V_SIGNING or sign_v_tls.kind != CERT_SIGNING_V_TLS_CERT:
        raise ChannelError("Ed25519 证书类型与 CERTS 字段不符")
    # Key type 01 on a type-05 certificate is accepted for legacy Tor compatibility.
    if id_v_sign.key_type != 1 or sign_v_tls.key_type not in (1, 3):
        raise ChannelError("中继证书的密钥类型不受支持")
    if not cert_tls_der:
        raise ChannelError("未收到对端 TLS 证书")
    identity = id_v_sign.signing_key
    if identity is None:
        raise ChannelError("IDENTITY_V_SIGNING 缺少签名密钥")
    id_v_sign.verify_signature(identity)                      # 由身份密钥自签名
    signing_key = id_v_sign.certified_key             # KP_relaysign_ed
    sign_v_tls.verify_signature(signing_key)
    if sign_v_tls.certified_key != hashlib.sha256(cert_tls_der).digest():
        raise ChannelError("SIGNING_V_TLS_CERT 与实际 TLS 证书不匹配")
    for c in (id_v_sign, sign_v_tls):
        if c.expired():
            raise ChannelError(f"类型 {c.kind} 的证书已过期（expired）")
    return identity


# --- NETINFO ------------------------------------------------------------------

def encode_address(ip: str) -> bytes:
    a = ipaddress.ip_address(ip)
    return bytes([4 if a.version == 4 else 6, len(a.packed)]) + a.packed


def decode_address(data: bytes, pos: int) -> tuple[str | None, int]:
    if pos < 0 or pos + 2 > len(data):
        raise ChannelError("NETINFO 地址头不完整")
    kind, length = data[pos], data[pos + 1]
    if pos + 2 + length > len(data):
        raise ChannelError("NETINFO 地址超出消息边界")
    value = data[pos + 2:pos + 2 + length]
    ip = None
    if (kind, length) in ((4, 4), (6, 16)):
        ip = str(ipaddress.ip_address(value))
    return ip, pos + 2 + length


def client_netinfo_cell(ip_relay: str) -> Cell:
    """客户端 NETINFO：时间戳为零，不提供自己的地址。"""
    body = struct.pack(">I", 0) + encode_address(ip_relay) + b"\x00"
    return Cell(0, CellCommand.NETINFO, body)


@dataclass
class Netinfo:
    timestamp: int
    peer_address: str | None
    my_addresses: list[str | None]


def decode_netinfo(body: bytes) -> Netinfo:
    if len(body) < 4:
        raise ChannelError("NETINFO 信元不完整")
    (timestamp,) = struct.unpack(">I", body[:4])
    peer, pos = decode_address(body, 4)
    if pos >= len(body):
        raise ChannelError("NETINFO 信元不完整")
    n, pos = body[pos], pos + 1
    my_addresses = []
    for _ in range(n):
        ip, pos = decode_address(body, pos)
        my_addresses.append(ip)
    return Netinfo(timestamp, peer, my_addresses)


 # --- Channel ----------------------------------------------------------------

@dataclass
class Channel:
    sock: ssl.SSLSocket
    version: int
    ed_identity: bytes
    netinfo: Netinfo
    auth_methods: list[int]
    buffer: bytes = b""
    registry: list[str] = field(default_factory=list)

    def send(self, cell: Cell) -> None:
        self.sock.sendall(encode(cell, self.version))

    def receive(self) -> Cell:
        while (r := decode(self.buffer, self.version)) is None:
            data = self.sock.recv(65536)
            if not data:
                raise ChannelError("中继关闭了连接")
            self.buffer += data
        cell, self.buffer = r
        return cell


def _read(sock, buffer: bytes, version: int) -> tuple[Cell, bytes]:
    while (r := decode(buffer, version)) is None:
        data = sock.recv(65536)
        if not data:
            raise ChannelError("握手期间连接被关闭")
        buffer += data
    return r


def open_channel(host: str, port: int, expected_identity: bytes | None = None,
                timeout: float = 10.0, source_address: str | None = None) -> Channel:
    """按照正式客户端的方式打开中继通道，不进行客户端身份认证。
    `source_address` 选择本地源地址（如 127.0.0.2）。"""
    # 未指定 expected_identity 时，CERTS 只能确认对端所声明的身份，不能确认预先选定的中继。
    # SSLKEYLOGFILE 会导出 TLS 会话密钥，仅可在受控私有实验环境中启用。
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # 中继 TLS 证书没有可信 CA 签名或可验证的域名；
    # 后续通过 CERTS cell 验证真实的中继身份。
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # 设置 SSLKEYLOGFILE 时，按照浏览器约定导出会话密钥，
    # 使 Wireshark 能解密我们自己的通道（第 20 章）。
    if os.environ.get("SSLKEYLOGFILE"):
        ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
    source = (source_address, 0) if source_address else None
    raw_sock = socket.create_connection((host, port), timeout=timeout,
                                        source_address=source)
    try:
        sock = ctx.wrap_socket(raw_sock)
    except BaseException:
        raw_sock.close()
        raise
    try:
        cert_tls = sock.getpeercert(binary_form=True)
        if not cert_tls:
            raise ChannelError("未收到对端 TLS 证书")
        registry = [f"TLS {sock.version()} {sock.cipher()[0]}"]
    
        sock.sendall(encode(versions_cell(SUPPORTED_VERSIONS), 0))
        buffer, version = b"", 0
        certificates, methods, netinfo = None, [], None
        while netinfo is None:
            cell, buffer = _read(sock, buffer, version)
            if not version and cell.command != CellCommand.VERSIONS:
                raise ChannelError("握手的第一个信元必须是 VERSIONS")
            registry.append(f"<- {(CellCommand._value2member_map_.get(cell.command).name if cell.command in CellCommand._value2member_map_ else cell.command)}（{len(cell.body)} 字节）")
            if cell.command == CellCommand.VERSIONS:
                if version:
                    continue                                  # 忽略后续 VERSIONS cell
                version = negotiate_version(SUPPORTED_VERSIONS, cell.body)
            elif cell.command == CellCommand.VPADDING:
                continue
            elif cell.command == CellCommand.CERTS:
                if certificates is not None:
                    raise ChannelError("重复的 CERTS 信元")
                certificates = decode_certs(cell.body)
            elif cell.command == CellCommand.AUTH_CHALLENGE:
                if len(cell.body) < 34:
                    raise ChannelError("AUTH_CHALLENGE 方法列表不完整")
                (n,) = struct.unpack(">H", cell.body[32:34])
                if len(cell.body) < 34 + 2 * n:
                    raise ChannelError("AUTH_CHALLENGE 方法列表不完整")
                methods = [m for (m,) in struct.iter_unpack(">H", cell.body[34:34 + 2 * n])]
            elif cell.command == CellCommand.NETINFO:
                netinfo = decode_netinfo(cell.body)
            else:
                raise ChannelError(f"握手中收到意外的 cell：{cell.command}")
    
        if not version:
            raise ChannelError("尚未通过 VERSIONS 协商链路版本")
        if certificates is None:
            raise ChannelError("在 CERTS 之前收到了 NETINFO")
        identity = verify_responder_identity(certificates, cert_tls)
        if expected_identity is not None and identity != expected_identity:
            raise ChannelError("中继身份与预期身份不一致")
    
        channel = Channel(sock, version, identity, netinfo, methods, buffer, registry)
        channel.send(client_netinfo_cell(sock.getpeername()[0]))
        registry.append("-> NETINFO：通道已建立")
        return channel
    except BaseException:
        sock.close()
        raise


def identity_from_file(path: str) -> bytes:
    """读取节点的 fingerprint-ed25519 文件，格式：'<name> <base64 key>'。"""
    b64 = open(path).read().split()[1]
    return base64.b64decode(b64 + "=" * (-len(b64) % 4))
