# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 1 — abrir un canal hacia un repetidor y comprobar su identidad.

Referencias: tor-spec, secciones de canales y negociación inicial;
cert-spec, certificados Ed25519 de Tor. Como un cliente Tor ordinario,
este cliente no se autentica: únicamente envía VERSIONS y NETINFO.
Módulo didáctico: utilizar solo en la red privada del libro.
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

SUPPORTED_VERSIONS = [4, 5]      # como Arti: sin versión 3 del protocolo de enlace

# Tipos de certificados en la celda CERTS (cert-spec, Certificate types).
CERT_RSA_ID_X509 = 0x02
CERT_IDENTITY_V_SIGNING = 0x04
CERT_SIGNING_V_TLS_CERT = 0x05
CERT_RSA_ID_V_IDENTITY = 0x07
EXT_SIGNED_WITH_ED25519_KEY = 0x04


class ChannelError(Exception):
    """Ha fallado el intercambio inicial del canal."""


 # --- Tor Ed25519 certificates ------------------------------------------------

@dataclass
class EdCertificate:
    kind: int
    expiration_hours: int            # horas desde la época Unix
    key_type: int
    certified_key: bytes    # 32 bytes
    extensions: dict[int, tuple[int, bytes]]   # tipo -> (indicador, datos)
    signed_data: bytes               # bytes incluidos en la firma
    signature: bytes

    @property
    def signing_key(self) -> bytes | None:
        """Clave de la extensión signed-with-ed25519-key, cuando existe."""
        est = self.extensions.get(EXT_SIGNED_WITH_ED25519_KEY)
        return est[1] if est else None

    def expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.expiration_hours * 3600 < now

    def verify_signature(self, public_key: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(self.signature, self.signed_data)
        except InvalidSignature:
            raise ChannelError(f"firma no válida en el certificado de tipo {self.kind}") from None


def decode_ed_certificate(data: bytes) -> EdCertificate:
    """Interpreta un certificado Ed25519 de Tor (cert-spec, ed-certs)."""
    if len(data) < 40 + 64 or data[0] != 1:
        raise ChannelError("certificado Ed25519 malformado o versión incompatible")
    _, kind, expiration, key_type = struct.unpack(">BBIB", data[:7])
    key = data[7:39]
    extension_count = data[39]
    pos, extensions = 40, {}
    for _ in range(extension_count):
        if pos + 4 > len(data) - 64:
            raise ChannelError("cabecera de extensión Ed25519 truncada")
        length, extension_type, flag = struct.unpack(">HBB", data[pos:pos + 4])
        if pos + 4 + length > len(data) - 64:
            raise ChannelError("certificado CERTS fuera del cuerpo de la celda")
        body = data[pos + 4:pos + 4 + length]
        if len(body) != length:
            raise ChannelError("la extensión sobrepasa el límite del certificado")
        if extension_type != EXT_SIGNED_WITH_ED25519_KEY and flag & 1:
            # Rechazar extensiones desconocidas con AFFECTS_VALIDATION.
            raise ChannelError(f"extensión desconocida {extension_type} que afecta a la validación")
        if extension_type in extensions:
            raise ChannelError("extensión Ed25519 duplicada")
        if extension_type == EXT_SIGNED_WITH_ED25519_KEY and length != 32:
            raise ChannelError("longitud inválida de la extensión de firma Ed25519")
        extensions[extension_type] = (flag, body)
        pos += 4 + length
    if len(data) != pos + 64:
        raise ChannelError("longitud de certificado incoherente")
    return EdCertificate(kind, expiration, key_type, key, extensions, data[:pos], data[pos:])


def decode_certs(body: bytes) -> dict[int, bytes]:
    """Cuerpo de CERTS -> {tipo de certificado: certificado sin procesar}."""
    if not body:
        raise ChannelError("celda CERTS vacía")
    n, pos, certificates = body[0], 1, {}
    for _ in range(n):
        if pos + 3 > len(body):
            raise ChannelError("cabecera de certificado CERTS truncada")
        kind, length = struct.unpack(">BH", body[pos:pos + 3])
        if pos + 3 + length > len(body):
            raise ChannelError("certificado CERTS fuera del cuerpo de la celda")
        if kind in certificates:
            raise ChannelError(f"varios certificados de tipo {kind}")
        certificates[kind] = body[pos + 3:pos + 3 + length]
        pos += 3 + length
    return certificates


def verify_responder_identity(certificates: dict[int, bytes], cert_tls_der: bytes) -> bytes:
    """Aplica las reglas para autenticar al repetidor mediante CERTS.

    Devuelve KP_relayid_ed (32 bytes) si es válida la cadena
        identidad Ed25519 -> clave de firma -> certificado TLS;
    de lo contrario, lanza ChannelError.
    """
    try:
        id_v_sign = decode_ed_certificate(certificates[CERT_IDENTITY_V_SIGNING])
        sign_v_tls = decode_ed_certificate(certificates[CERT_SIGNING_V_TLS_CERT])
    except KeyError as e:
        raise ChannelError(f"falta el certificado de tipo {e.args[0]}") from None

    if id_v_sign.kind != CERT_IDENTITY_V_SIGNING or sign_v_tls.kind != CERT_SIGNING_V_TLS_CERT:
        raise ChannelError("el tipo Ed25519 no coincide con la entrada CERTS")
    # Key type 01 on a type-05 certificate is accepted for legacy Tor compatibility.
    if id_v_sign.key_type != 1 or sign_v_tls.key_type not in (1, 3):
        raise ChannelError("tipo de clave no admitido para el certificado del repetidor")
    if not cert_tls_der:
        raise ChannelError("falta el certificado TLS del par")
    identity = id_v_sign.signing_key
    if identity is None:
        raise ChannelError("IDENTITY_V_SIGNING sin clave de firma")
    id_v_sign.verify_signature(identity)                      # firmado con la propia clave de identidad
    signing_key = id_v_sign.certified_key             # KP_relaysign_ed
    sign_v_tls.verify_signature(signing_key)
    if sign_v_tls.certified_key != hashlib.sha256(cert_tls_der).digest():
        raise ChannelError("SIGNING_V_TLS_CERT no coincide con el certificado TLS recibido")
    for c in (id_v_sign, sign_v_tls):
        if c.expired():
            raise ChannelError(f"certificado de tipo {c.kind} caducado")
    return identity


# --- NETINFO ------------------------------------------------------------------

def encode_address(ip: str) -> bytes:
    a = ipaddress.ip_address(ip)
    return bytes([4 if a.version == 4 else 6, len(a.packed)]) + a.packed


def decode_address(data: bytes, pos: int) -> tuple[str | None, int]:
    if pos < 0 or pos + 2 > len(data):
        raise ChannelError("dirección NETINFO truncada")
    kind, length = data[pos], data[pos + 1]
    if pos + 2 + length > len(data):
        raise ChannelError("la dirección NETINFO excede el cuerpo")
    value = data[pos + 2:pos + 2 + length]
    ip = None
    if (kind, length) in ((4, 4), (6, 16)):
        ip = str(ipaddress.ip_address(value))
    return ip, pos + 2 + length


def client_netinfo_cell(ip_relay: str) -> Cell:
    """NETINFO del cliente: marca temporal cero y ninguna dirección propia."""
    body = struct.pack(">I", 0) + encode_address(ip_relay) + b"\x00"
    return Cell(0, CellCommand.NETINFO, body)


@dataclass
class Netinfo:
    timestamp: int
    peer_address: str | None
    my_addresses: list[str | None]


def decode_netinfo(body: bytes) -> Netinfo:
    if len(body) < 4:
        raise ChannelError("celda NETINFO truncada")
    (timestamp,) = struct.unpack(">I", body[:4])
    peer, pos = decode_address(body, 4)
    if pos >= len(body):
        raise ChannelError("celda NETINFO truncada")
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
                raise ChannelError("conexión cerrada por el repetidor")
            self.buffer += data
        cell, self.buffer = r
        return cell


def _read(sock, buffer: bytes, version: int) -> tuple[Cell, bytes]:
    while (r := decode(buffer, version)) is None:
        data = sock.recv(65536)
        if not data:
            raise ChannelError("conexión cerrada durante el intercambio inicial")
        buffer += data
    return r


def open_channel(host: str, port: int, expected_identity: bytes | None = None,
                timeout: float = 10.0, source_address: str | None = None) -> Channel:
    """Abre un canal hacia un repetidor sin autenticación del cliente.
    `source_address` selecciona la dirección local de origen (p. ej. 127.0.0.2)."""
    # Sin expected_identity, CERTS solo autentica la identidad declarada por el repetidor, no un repetidor elegido previamente.
    # SSLKEYLOGFILE revela secretos TLS: úsalo únicamente en un laboratorio privado controlado.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # El certificado TLS del repetidor es autofirmado y no tiene dominio:
    # la identidad se verifica después mediante CERTS.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Si se define SSLKEYLOGFILE, guardar las claves de sesión según la
    # convención del navegador para descifrar *nuestro* canal (capítulo 20).
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
            raise ChannelError("falta el certificado TLS del par")
        registry = [f"TLS {sock.version()} {sock.cipher()[0]}"]
    
        sock.sendall(encode(versions_cell(SUPPORTED_VERSIONS), 0))
        buffer, version = b"", 0
        certificates, methods, netinfo = None, [], None
        while netinfo is None:
            cell, buffer = _read(sock, buffer, version)
            if not version and cell.command != CellCommand.VERSIONS:
                raise ChannelError("la primera celda del intercambio debe ser VERSIONS")
            registry.append(f"<- {(CellCommand._value2member_map_.get(cell.command).name if cell.command in CellCommand._value2member_map_ else cell.command)} ({len(cell.body)} bytes)")
            if cell.command == CellCommand.VERSIONS:
                if version:
                    continue                                  # ignorar las celdas VERSIONS posteriores
                version = negotiate_version(SUPPORTED_VERSIONS, cell.body)
            elif cell.command == CellCommand.VPADDING:
                continue
            elif cell.command == CellCommand.CERTS:
                if certificates is not None:
                    raise ChannelError("celda CERTS duplicada")
                certificates = decode_certs(cell.body)
            elif cell.command == CellCommand.AUTH_CHALLENGE:
                if len(cell.body) < 34:
                    raise ChannelError("lista de métodos AUTH_CHALLENGE truncada")
                (n,) = struct.unpack(">H", cell.body[32:34])
                if len(cell.body) < 34 + 2 * n:
                    raise ChannelError("lista de métodos AUTH_CHALLENGE truncada")
                methods = [m for (m,) in struct.iter_unpack(">H", cell.body[34:34 + 2 * n])]
            elif cell.command == CellCommand.NETINFO:
                netinfo = decode_netinfo(cell.body)
            else:
                raise ChannelError(f"celda inesperada durante el intercambio inicial: {cell.command}")
    
        if not version:
            raise ChannelError("no se negoció VERSIONS")
        if certificates is None:
            raise ChannelError("NETINFO recibido antes de CERTS")
        identity = verify_responder_identity(certificates, cert_tls)
        if expected_identity is not None and identity != expected_identity:
            raise ChannelError("la identidad del repetidor es distinta de la esperada")
    
        channel = Channel(sock, version, identity, netinfo, methods, buffer, registry)
        channel.send(client_netinfo_cell(sock.getpeername()[0]))
        registry.append("-> NETINFO: canal abierto")
        return channel
    except BaseException:
        sock.close()
        raise


def identity_from_file(path: str) -> bytes:
    """Lee el archivo fingerprint-ed25519 de un nodo: «<nombre> <clave base64>»."""
    b64 = open(path).read().split()[1]
    return base64.b64decode(b64 + "=" * (-len(b64) % 4))
