# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""附录 B：将 X25519（Montgomery）公钥转换为 Ed25519（Edwards）公钥。

规范依据：dir-spec 的 Converting a curve25519 public key to an ed25519 public key。
该转换用于验证描述符中的 ntor-onion-key-crosscert 字段：
使用中继的 ntor 公钥转换到 Edwards 形式后验证 Ed25519 交叉证书。
"""
from __future__ import annotations

import base64
import re

P = 2**255 - 19


def montgomery_to_edwards(u_bytes: bytes, sign: int) -> bytes:
    """Montgomery 的 u 坐标（32 字节小端）转换为压缩的 Ed25519 公钥。

    y = (u - 1) / (u + 1) mod p；压缩公钥以小端方式保存 y，
    最后一个字节的最高位保存 x 坐标的符号位。
    """
    if len(u_bytes) != 32:
        raise ValueError("ntor 公钥长度必须恰好为 32 字节")
    if sign not in (0, 1):
        raise ValueError("Edwards 符号位只能为 0 或 1")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    if (u + 1) % P == 0:
        raise ValueError("无效的 u 坐标：分母不可逆")
    y = (u - 1) * pow(u + 1, P - 2, P) % P
    compressed = bytearray(y.to_bytes(32, "little"))
    compressed[31] |= (sign & 1) << 7
    return bytes(compressed)


def _decode_ntor_key(value: str) -> bytes:
    """严格解码 base64 编码的 ntor 公钥。"""
    result = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if len(result) != 32:
        raise ValueError("ntor 公钥长度必须恰好为 32 字节")
    return result


def verify_crosscert(ntor_onion_key_b64: str, sign: int, cert: bytes) -> bytes:
    """使用转换后的 ntor 公钥验证证书签名，返回经过认证的公钥
    （中继的主要 Ed25519 身份）。
    调用方还必须与描述符的 master-key-ed25519 字段进行比对。"""
    from .channel import decode_ed_certificate
    u = _decode_ntor_key(ntor_onion_key_b64)
    c = decode_ed_certificate(cert)
    if c.kind != 0x0A or c.key_type != 1:
        raise ValueError("ntor 交叉证书的类型必须为 0x0A，且认证 Ed25519 公钥")
    if c.signing_key is not None:
        raise ValueError("ntor 交叉证书不得包含额外的签名公钥扩展")
    c.verify_signature(montgomery_to_edwards(u, sign))
    if c.expired():
        raise ValueError("ntor 交叉证书已过期")
    return c.certified_key


def _pem(text: str) -> bytes:
    lines = [r.strip() for r in text.splitlines() if r.strip() and not r.startswith("-----")]
    return base64.b64decode("".join(lines), validate=True)


if __name__ == "__main__":
    import sys
    descriptor = open(sys.argv[1], encoding="utf-8").read()
    name = sys.argv[2]
    entry = [x for x in re.split(r"(?m)^router ", descriptor) if x.startswith(name + " ")][-1]
    ntor = entry.split("\nntor-onion-key ")[1].split()[0]
    after = entry.split("\nntor-onion-key-crosscert ")[1]
    sign = int(after.split()[0])
    pem = after.split("-----BEGIN ED25519 CERT-----", 1)[1].split("-----END ED25519 CERT-----")[0]
    identity = verify_crosscert(ntor, sign, _pem(pem))
    print(f"{name}: ntor-onion-key {ntor}")
    print(f"  Edwards 公钥（符号位 {sign}）： {montgomery_to_edwards(_decode_ntor_key(ntor), sign).hex()}")
    print(f"  交叉证书验证成功；已认证的身份： {base64.b64encode(identity).decode().rstrip('=')}")
