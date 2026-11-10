# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 8：v3 洋葱服务的地址、盲化密钥、HSDir 与描述符。

规范依据：rend-spec 中 Encoding onion addresses、Deriving blinded keys and
subcredentials、Locating, uploading, and downloading hidden service descriptors、
Hidden service descriptors: encryption format 和附录 A（密钥盲化）。
只供本书私有实验网络使用。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .channel import decode_ed_certificate

 # --- .onion 地址 -------------------------------------------------------------

VERSION = 3


def _require_bytes(value: bytes, size: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{label} 必须恰好包含 {size} 字节")


def _require_u64(value: int, label: str, *, positive: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value < 2 ** 64):
        raise ValueError(f"{label} 必须是非负 uint64")
    if positive and value == 0:
        raise ValueError(f"{label} 必须为正数")




def onion_address(key: bytes) -> str:
    """从 32 字节 Ed25519 公钥编码规范的 v3 onion 地址。"""
    _require_bytes(key, 32, "onion 身份公钥")
    checksum = hashlib.sha3_256(b".onion checksum" + key + bytes([VERSION])).digest()[:2]
    return base64.b32encode(key + checksum + bytes([VERSION])).decode("ascii").lower() + ".onion"

def key_from_address(address: str) -> bytes:
    """检查主机名、Base32 字母表、版本和校验和。"""
    if not isinstance(address, str):
        raise ValueError("v3 onion 地址无效")
    canonical = address.lower()
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", canonical):
        raise ValueError("v3 onion 地址无效")
    raw = base64.b32decode(canonical[:-6].upper(), casefold=False)
    key, checksum, version = raw[:32], raw[32:34], raw[34]
    if version != VERSION:
        raise ValueError("不支持的 v3 onion 地址版本")
    expected = hashlib.sha3_256(b".onion checksum" + key + bytes([version])).digest()[:2]
    if not hmac.compare_digest(expected, checksum):
        raise ValueError("v3 onion 地址校验和无效")
    return key

# --- Ed25519 算术（RFC 8032），仅实现密钥盲化所需部分 ----------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _x_from_y(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * I % P
    if (x * x - xx) % P:
        raise ValueError("无效的曲线点")
    return P - x if x & 1 != sign else x


def _decode_point(b: bytes) -> tuple[int, int, int, int]:
    """解码规范的压缩 Ed25519 点（不验证子群）。"""
    _require_bytes(b, 32, "压缩的 Ed25519 点")
    encoded = int.from_bytes(b, "little")
    sign, y = encoded >> 255, encoded & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("非规范 Ed25519 编码")
    x = _x_from_y(y, sign)
    if x % P == 0 and sign:   # RFC 8032 5.1.3
        raise ValueError("Ed25519 符号位编码不规范")
    return (x, y, 1, x * y % P)

def _encode_point(p) -> bytes:
    x, y, z, _ = p
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _multiply(k: int, p):
    r = (0, 1, 1, 0)                               # 单位元
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


# 计算 h 时所用的规范基点文本表示。
BASE_STR = (b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, "
            b"46316835694926478169428394003475163141307993866256225615783033603165251855960)")


def blinding_factor(A: bytes, period: int, duration_minutes: int) -> int:
    _require_bytes(A, 32, "服务身份公钥")
    _require_u64(period, "time period")
    _require_u64(duration_minutes, "时间周期持续时间", positive=True)
    n = b"key-blind" + struct.pack(">QQ", period, duration_minutes)
    h = bytearray(hashlib.sha3_256(b"Derive temporary signing key\x00" + A + BASE_STR + n).digest())
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")

def blinded_key(A: bytes, period: int, duration_minutes: int) -> bytes:
    """A' = h·A：指定周期使用的服务公钥。"""
    return _encode_point(_multiply(blinding_factor(A, period, duration_minutes), _decode_point(A)))


def credential(A: bytes) -> bytes:
    _require_bytes(A, 32, "服务身份公钥")
    return hashlib.sha3_256(b"credential" + A).digest()

def subcredential(A: bytes, blinded: bytes) -> bytes:
    _require_bytes(blinded, 32, "服务盲化公钥")
    return hashlib.sha3_256(b"subcredential" + credential(A) + blinded).digest()

# --- 时间周期与 HSDir 环 ----------------------------------------------

SR_ROUNDS = 12            # SHARED_RANDOM_N_ROUNDS；共享随机协议的一个阶段


@dataclass
class TimePeriodInfo:
    period: int
    duration_minutes: int
    uses_current_srv: bool


def time_period_info(valid_after: int, voting_interval: int, test_network: bool) -> TimePeriodInfo:
    """根据共识投票时间表计算 HS 周期。"""
    _require_u64(valid_after, "valid-after")
    _require_u64(voting_interval, "投票间隔", positive=True)
    phase = SR_ROUNDS * voting_interval
    if phase < 60 or phase % 60 or 2 * phase >= 2 ** 64:
        raise ValueError("SRV 阶段持续时间无效")
    duration = (2 * phase if test_network else 24 * 3600) // 60
    minutes = valid_after // 60 - phase // 60
    period = minutes // duration
    if period < 0:
        raise ValueError("时间周期早于 Unix 纪元")
    within_cycle = valid_after % (2 * phase)
    return TimePeriodInfo(period, duration, within_cycle >= phase)

def disaster_srv(t: TimePeriodInfo) -> bytes:
    _require_u64(t.period, "time period")
    _require_u64(t.duration_minutes, "duration", positive=True)
    return hashlib.sha3_256(b"shared-random-disaster" + struct.pack(">QQ", t.duration_minutes, t.period)).digest()

def service_index(blinded: bytes, replica: int, t: TimePeriodInfo) -> bytes:
    _require_bytes(blinded, 32, "服务盲化公钥")
    _require_u64(replica, "replica", positive=True)
    _require_u64(t.period, "time period")
    _require_u64(t.duration_minutes, "duration", positive=True)
    return hashlib.sha3_256(b"store-at-idx" + blinded + struct.pack(">QQQ", replica, t.duration_minutes, t.period)).digest()

def relay_index(id_ed: bytes, srv: bytes, t: TimePeriodInfo) -> bytes:
    _require_bytes(id_ed, 32, "HSDir Ed25519 身份")
    _require_bytes(srv, 32, "共享随机值")
    _require_u64(t.period, "time period")
    _require_u64(t.duration_minutes, "duration", positive=True)
    return hashlib.sha3_256(b"node-idx" + id_ed + srv + struct.pack(">QQ", t.period, t.duration_minutes)).digest()

def responsible_hsdirs(blinded: bytes, hsdir: list[tuple[str, bytes]], srv: bytes, t: TimePeriodInfo,
                       replicas: int = 2, spread: int = 3) -> list[list[str]]:
    """为各副本选择不同 HSDir；拒绝数量不足的节点环。"""
    _require_bytes(blinded, 32, "服务盲化公钥")
    _require_bytes(srv, 32, "共享随机值")
    if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas <= 0:
        raise ValueError("副本数量必须为正数")
    if not isinstance(spread, int) or isinstance(spread, bool) or spread <= 0:
        raise ValueError("HSDir 分散数量必须为正数")
    if len(hsdir) < replicas * spread:
        raise ValueError("HSDir 数量不足，无法分配不同节点")
    names = [name for name, _ in hsdir]
    if len(set(names)) != len(names):
        raise ValueError("HSDir 名称重复")
    ring = sorted((relay_index(ed, srv, t), name) for name, ed in hsdir)
    selected, result = set(), []
    for replica in range(1, replicas + 1):
        idx = service_index(blinded, replica, t)
        start = next((i for i, (x, _) in enumerate(ring) if x > idx), 0)
        group = []
        for k in range(len(ring)):
            name = ring[(start + k) % len(ring)][1]
            if name not in selected:
                group.append(name)
                selected.add(name)
                if len(group) == spread:
                    break
        result.append(group)
    return result

# --- 描述符 ----------------------------------------------------------------------

def _decrypt_layer(blob: bytes, secret_data: bytes, subcred: bytes, revision: int,
                    constant: bytes) -> bytes:
    """先验证 SALT | 密文 | MAC，再进行解密。"""
    if len(blob) < 48:
        raise ValueError("加密描述符层被截断")
    _require_bytes(secret_data, 32, "描述符加密秘密")
    _require_bytes(subcred, 32, "描述符子凭据")
    _require_u64(revision, "描述符修订编号")
    salt, ciphertext, mac = blob[:16], blob[16:-32], blob[-32:]
    input_data = secret_data + subcred + struct.pack(">Q", revision) + salt + constant
    keys = hashlib.shake_256(input_data).digest(80)
    k, iv, k_mac = keys[:32], keys[32:48], keys[48:]
    expected = hashlib.sha3_256(struct.pack(">Q", 32) + k_mac + struct.pack(">Q", 16) + salt
                              + ciphertext).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("加密描述符 MAC 无效")
    d = Cipher(algorithms.AES(k), modes.CTR(iv)).decryptor()
    return (d.update(ciphertext) + d.finalize()).rstrip(b"\x00")

def _object_block(text: str, keyword: str) -> bytes:
    """提取唯一的 PEM 格式对象，并严格检查 Base64。"""
    lines = text.splitlines()
    positions = [i for i, line in enumerate(lines) if line == keyword]
    if len(positions) != 1:
        raise ValueError("描述符对象缺失或重复")
    pos = positions[0]
    if pos + 2 >= len(lines):
        raise ValueError("描述符对象被截断")
    begin = lines[pos + 1]
    marker = {"descriptor-signing-key-cert": "ED25519 CERT"}.get(keyword, "MESSAGE")
    if begin != f"-----BEGIN {marker}-----":
        raise ValueError("描述符对象头无效")
    try:
        end = lines.index(f"-----END {marker}-----", pos + 2)
    except ValueError:
        raise ValueError("描述符对象未结束") from None
    encoded = "".join(lines[pos + 2:end])
    if not encoded:
        raise ValueError("描述符对象为空")
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("描述符对象 Base64 无效") from None

@dataclass
class Descriptor:
    duration_minutes: int
    revision: int
    signing_key: bytes
    introduction_points: list[str]
    inner_layer: str


def parse_descriptor(text: str, A: bytes, blinded: bytes, *, check_expiration: bool = False,
                     reference_time: float | None = None) -> Descriptor:
    """解析带签名的 HSv3 描述符；可选验证证书有效期。

    历史实验样例可以使用 check_expiration=False。
    实际客户端必须检查有效期并认证目录信息。
    教学解码器不支持 restricted discovery 描述符。
    """
    _require_bytes(A, 32, "服务身份公钥")
    _require_bytes(blinded, 32, "服务盲化公钥")
    if not text.startswith("hs-descriptor 3\n"):
        raise ValueError("不支持的隐藏服务描述符版本")
    lines = {}
    for row in text.splitlines():
        if row.startswith(("descriptor-lifetime ", "revision-counter ", "signature ")):
            keyword, value = row.split(" ", 1)
            if keyword in lines:
                raise ValueError("描述符字段重复")
            lines[keyword] = value
    if any(k not in lines for k in ("descriptor-lifetime", "revision-counter", "signature")):
        raise ValueError("缺少描述符字段")
    lifetime = int(lines["descriptor-lifetime"])
    if not 30 <= lifetime <= 720:
        raise ValueError("描述符有效期超出范围")
    revision = int(lines["revision-counter"])
    _require_u64(revision, "描述符修订编号")
    signature_marker = "\nsignature "
    if text.count(signature_marker) != 1 or not text.splitlines()[-1].startswith("signature "):
        raise ValueError("描述符签名必须在最后一行")
    subcred = subcredential(A, blinded)
    cert = decode_ed_certificate(_object_block(text, "descriptor-signing-key-cert"))
    if cert.kind != 0x08 or cert.key_type != 0x01 or cert.signing_key != blinded:
        raise ValueError("签名证书未绑定盲化身份")
    if check_expiration and cert.expired(reference_time):
        raise ValueError("描述符签名证书已过期")
    cert.verify_signature(blinded)
    signing_key = cert.certified_key
    body = text[:text.index(signature_marker) + 1].encode("utf-8")
    try:
        signature = base64.b64decode(lines["signature"] + "=" * (-len(lines["signature"]) % 4), validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("描述符签名 Base64 无效") from None
    if len(signature) != 64:
        raise ValueError("描述符签名长度无效")
    try:
        Ed25519PublicKey.from_public_bytes(signing_key).verify(
            signature, b"Tor onion service descriptor sig v3" + body)
    except InvalidSignature:
        raise ValueError("描述符签名无效") from None
    outer = _decrypt_layer(_object_block(text, "superencrypted"), blinded, subcred, revision,
                              b"hsdir-superencrypted-data").decode("utf-8")
    inner = _decrypt_layer(_object_block(outer, "encrypted"), blinded, subcred, revision,
                              b"hsdir-encrypted-data").decode("utf-8")
    introduction_points = [r.split(" ", 1)[1] for r in inner.splitlines()
                           if r.startswith("introduction-point ")]
    return Descriptor(lifetime, revision, signing_key, introduction_points, inner)

def download_descriptor(blinded: bytes, path: list) -> str:
    """通过实验网络专用匿名 HSDir 电路获取描述符。

    要求三个跳点；不保证公共网络上的匿名性。
    """
    _require_bytes(blinded, 32, "服务盲化公钥")
    if len(path) < 3:
        raise ValueError("HSDir 描述符请求需要至少三个跳点")
    from .circuit import build
    from .directory import download
    url = "/tor/hs/3/" + base64.b64encode(blinded).decode("ascii").rstrip("=")
    return download(build(path, cc=False), url, 1).decode("utf-8")