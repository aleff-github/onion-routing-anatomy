# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 1 — открыть канал к ретранслятору и проверить его идентичность.

Источники: tor-spec, "Channels" и "Negotiating and initializing channels";
cert-spec, "Tor Ed25519 Certificates". Клиент не аутентифицируется, как и обычные клиенты Tor:
он отправляет только VERSIONS и NETINFO.
Учебный модуль: использовать только в приватной лабораторной сети книги.
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

SUPPORTED_VERSIONS = [4, 5]      # как в Arti: без версии 3 протокола канала

# Типы сертификатов в ячейке CERTS (cert-spec, "Certificate types").
CERT_RSA_ID_X509 = 0x02
CERT_IDENTITY_V_SIGNING = 0x04
CERT_SIGNING_V_TLS_CERT = 0x05
CERT_RSA_ID_V_IDENTITY = 0x07
EXT_SIGNED_WITH_ED25519_KEY = 0x04


class ChannelError(Exception):
    """Ошибка установления канала."""


 # --- Сертификаты Tor Ed25519 ------------------------------------------------

@dataclass
class EdCertificate:
    kind: int
    expiration_hours: int            # часов с начала эпохи Unix
    key_type: int
    certified_key: bytes    # 32 байта
    extensions: dict[int, tuple[int, bytes]]   # тип -> (флаг, данные)
    signed_data: bytes               # байты, покрываемые подписью
    signature: bytes

    @property
    def signing_key(self) -> bytes | None:
        """Ключ из расширения signed-with-ed25519-key, если оно присутствует."""
        est = self.extensions.get(EXT_SIGNED_WITH_ED25519_KEY)
        return est[1] if est else None

    def expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.expiration_hours * 3600 < now

    def verify_signature(self, public_key: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(self.signature, self.signed_data)
        except InvalidSignature:
            raise ChannelError(f"неверная подпись сертификата типа {self.kind}") from None


def decode_ed_certificate(data: bytes) -> EdCertificate:
    """Разобрать сертификат Tor Ed25519 (cert-spec, ed-certs)."""
    if len(data) < 40 + 64 or data[0] != 1:
        raise ChannelError("некорректный Ed25519-сертификат или неподдерживаемая версия")
    _, kind, expiration, key_type = struct.unpack(">BBIB", data[:7])
    key = data[7:39]
    extension_count = data[39]
    pos, extensions = 40, {}
    for _ in range(extension_count):
        if pos + 4 > len(data) - 64:
            raise ChannelError("усечён заголовок расширения сертификата Ed25519")
        length, extension_type, flag = struct.unpack(">HBB", data[pos:pos + 4])
        if pos + 4 + length > len(data) - 64:
            raise ChannelError("сертификат CERTS выходит за границы ячейки")
        body = data[pos + 4:pos + 4 + length]
        if len(body) != length:
            raise ChannelError("расширение выходит за границы сертификата")
        if extension_type != EXT_SIGNED_WITH_ED25519_KEY and flag & 1:
            # Отклонить неизвестное расширение с флагом AFFECTS_VALIDATION.
            raise ChannelError(f"неизвестное расширение {extension_type}, влияющее на проверку")
        if extension_type in extensions:
            raise ChannelError("повторяющееся расширение сертификата Ed25519")
        if extension_type == EXT_SIGNED_WITH_ED25519_KEY and length != 32:
            raise ChannelError("неверная длина расширения ключа подписи Ed25519")
        extensions[extension_type] = (flag, body)
        pos += 4 + length
    if len(data) != pos + 64:
        raise ChannelError("несогласованная длина сертификата")
    return EdCertificate(kind, expiration, key_type, key, extensions, data[:pos], data[pos:])


def decode_certs(body: bytes) -> dict[int, bytes]:
    """Содержимое ячейки CERTS -> {CertType: исходные байты сертификата}."""
    if not body:
        raise ChannelError("пустая ячейка CERTS")
    n, pos, certificates = body[0], 1, {}
    for _ in range(n):
        if pos + 3 > len(body):
            raise ChannelError("усечён заголовок сертификата в CERTS")
        kind, length = struct.unpack(">BH", body[pos:pos + 3])
        if pos + 3 + length > len(body):
            raise ChannelError("сертификат CERTS выходит за границы ячейки")
        if kind in certificates:
            raise ChannelError(f"более одного сертификата типа {kind}")
        certificates[kind] = body[pos + 3:pos + 3 + length]
        pos += 3 + length
    return certificates


def verify_responder_identity(certificates: dict[int, bytes], cert_tls_der: bytes) -> bytes:
    """Применить правила раздела "Authenticating the responder from its CERTS".

    Вернуть KP_relayid_ed (32 байта), если цепочка
        идентичность Ed25519 -> ключ подписи -> сертификат TLS
    действительна; иначе вызвать ChannelError.
    """
    try:
        id_v_sign = decode_ed_certificate(certificates[CERT_IDENTITY_V_SIGNING])
        sign_v_tls = decode_ed_certificate(certificates[CERT_SIGNING_V_TLS_CERT])
    except KeyError as e:
        raise ChannelError(f"отсутствует сертификат типа {e.args[0]}") from None

    if id_v_sign.kind != CERT_IDENTITY_V_SIGNING or sign_v_tls.kind != CERT_SIGNING_V_TLS_CERT:
        raise ChannelError("тип сертификата Ed25519 не соответствует записи CERTS")
    # Key type 01 on a type-05 certificate is accepted for legacy Tor compatibility.
    if id_v_sign.key_type != 1 or sign_v_tls.key_type not in (1, 3):
        raise ChannelError("недопустимый тип ключа сертификата реле")
    if not cert_tls_der:
        raise ChannelError("отсутствует TLS-сертификат узла")
    identity = id_v_sign.signing_key
    if identity is None:
        raise ChannelError("IDENTITY_V_SIGNING без ключа подписи")
    id_v_sign.verify_signature(identity)                      # самоподписан ключом идентичности
    signing_key = id_v_sign.certified_key             # KP_relaysign_ed
    sign_v_tls.verify_signature(signing_key)
    if sign_v_tls.certified_key != hashlib.sha256(cert_tls_der).digest():
        raise ChannelError("TLS: SIGNING_V_TLS_CERT не соответствует полученному TLS-сертификату")
    for c in (id_v_sign, sign_v_tls):
        if c.expired():
            raise ChannelError(f"сертификат типа {c.kind} просрочен")
    return identity


# --- NETINFO ------------------------------------------------------------------

def encode_address(ip: str) -> bytes:
    a = ipaddress.ip_address(ip)
    return bytes([4 if a.version == 4 else 6, len(a.packed)]) + a.packed


def decode_address(data: bytes, pos: int) -> tuple[str | None, int]:
    if pos < 0 or pos + 2 > len(data):
        raise ChannelError("усечён адрес в NETINFO")
    kind, length = data[pos], data[pos + 1]
    if pos + 2 + length > len(data):
        raise ChannelError("адрес NETINFO выходит за границы сообщения")
    value = data[pos + 2:pos + 2 + length]
    ip = None
    if (kind, length) in ((4, 4), (6, 16)):
        ip = str(ipaddress.ip_address(value))
    return ip, pos + 2 + length


def client_netinfo_cell(ip_relay: str) -> Cell:
    """NETINFO клиента: нулевая метка времени и отсутствие собственного адреса."""
    body = struct.pack(">I", 0) + encode_address(ip_relay) + b"\x00"
    return Cell(0, CellCommand.NETINFO, body)


@dataclass
class Netinfo:
    timestamp: int
    peer_address: str | None
    my_addresses: list[str | None]


def decode_netinfo(body: bytes) -> Netinfo:
    if len(body) < 4:
        raise ChannelError("усечена ячейка NETINFO")
    (timestamp,) = struct.unpack(">I", body[:4])
    peer, pos = decode_address(body, 4)
    if pos >= len(body):
        raise ChannelError("усечена ячейка NETINFO")
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
                raise ChannelError("ретранслятор закрыл соединение")
            self.buffer += data
        cell, self.buffer = r
        return cell


def _read(sock, buffer: bytes, version: int) -> tuple[Cell, bytes]:
    while (r := decode(buffer, version)) is None:
        data = sock.recv(65536)
        if not data:
            raise ChannelError("соединение закрыто во время установления канала")
        buffer += data
    return r


def open_channel(host: str, port: int, expected_identity: bytes | None = None,
                timeout: float = 10.0, source_address: str | None = None) -> Channel:
    """Открыть канал к ретранслятору как обычный клиент, без аутентификации клиента.
    `source_address` выбирает локальный адрес источника (например 127.0.0.2)."""
    # Без expected_identity цепочка CERTS подтверждает только заявленную реле идентичность, но не принадлежность выбранному узлу.
    # SSLKEYLOGFILE раскрывает секреты TLS; используйте его только в контролируемой лабораторной сети.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # TLS-сертификат реле самоподписан и не содержит доменного имени:
    # идентичность проверяется позже через ячейку CERTS.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Если задан SSLKEYLOGFILE, записать туда ключи сессии по соглашению браузеров,
    # чтобы Wireshark мог расшифровать *наш* канал (глава 20).
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
            raise ChannelError("отсутствует TLS-сертификат узла")
        registry = [f"TLS {sock.version()} {sock.cipher()[0]}"]
    
        sock.sendall(encode(versions_cell(SUPPORTED_VERSIONS), 0))
        buffer, version = b"", 0
        certificates, methods, netinfo = None, [], None
        while netinfo is None:
            cell, buffer = _read(sock, buffer, version)
            if not version and cell.command != CellCommand.VERSIONS:
                raise ChannelError("первой ячейкой согласования должна быть VERSIONS")
            registry.append(f"<- {(CellCommand._value2member_map_.get(cell.command).name if cell.command in CellCommand._value2member_map_ else cell.command)} ({len(cell.body)} байт)")
            if cell.command == CellCommand.VERSIONS:
                if version:
                    continue                                  # последующие ячейки VERSIONS игнорируются
                version = negotiate_version(SUPPORTED_VERSIONS, cell.body)
            elif cell.command == CellCommand.VPADDING:
                continue
            elif cell.command == CellCommand.CERTS:
                if certificates is not None:
                    raise ChannelError("повторная ячейка CERTS")
                certificates = decode_certs(cell.body)
            elif cell.command == CellCommand.AUTH_CHALLENGE:
                if len(cell.body) < 34:
                    raise ChannelError("усечён список методов AUTH_CHALLENGE")
                (n,) = struct.unpack(">H", cell.body[32:34])
                if len(cell.body) < 34 + 2 * n:
                    raise ChannelError("усечён список методов AUTH_CHALLENGE")
                methods = [m for (m,) in struct.iter_unpack(">H", cell.body[34:34 + 2 * n])]
            elif cell.command == CellCommand.NETINFO:
                netinfo = decode_netinfo(cell.body)
            else:
                raise ChannelError(f"неожиданная ячейка во время установления канала: {cell.command}")
    
        if not version:
            raise ChannelError("версия канала VERSIONS не согласована")
        if certificates is None:
            raise ChannelError("NETINFO получена до CERTS")
        identity = verify_responder_identity(certificates, cert_tls)
        if expected_identity is not None and identity != expected_identity:
            raise ChannelError("идентичность ретранслятора отличается от ожидаемой")
    
        channel = Channel(sock, version, identity, netinfo, methods, buffer, registry)
        channel.send(client_netinfo_cell(sock.getpeername()[0]))
        registry.append("-> NETINFO: канал открыт")
        return channel
    except BaseException:
        sock.close()
        raise


def identity_from_file(path: str) -> bytes:
    """Прочитать файл fingerprint-ed25519 узла: '<name> <base64 key>'."""
    b64 = open(path).read().split()[1]
    return base64.b64decode(b64 + "=" * (-len(b64) % 4))
