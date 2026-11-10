# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 9：洋葱服务工作量证明的 Blake2b 接受条件。

这只是统计教学模拟。随机生成的 16 字节候选值并非 Equi-X 解，
因此通过本检查不代表获得有效的 Tor 工作量证明。
正式验证还需要 Equi-X、可信描述符、有效的种子和 nonce 防重放机制
（hspow-spec，v1 方案）。
"""
from __future__ import annotations

import hashlib
import os
import struct

P_STRING = b"Tor hs intro v1\x00"  # Tor v1 个性化字符串；不得翻译协议字节
UINT32_MAX = 2 ** 32 - 1
UINT128_MAX = 2 ** 128 - 1


def _fixed_bytes(value: bytes, length: int, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{label} 长度必须恰好为 {length} 字节")


def _effort(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT32_MAX:
        raise ValueError("必须是无符号 32 位整数")


def check_value(service_id: bytes, seed: bytes, nonce: bytes, effort: int,
                solution: bytes) -> int:
    """计算 R：将 BLAKE2b-32(P | ID | C | N | E | S) 视为大端整数。"""
    _fixed_bytes(service_id, 32, "盲化服务身份")
    _fixed_bytes(seed, 32, "PoW 种子")
    _fixed_bytes(nonce, 16, "PoW nonce")
    _fixed_bytes(solution, 16, "Equi-X 证明字节")
    _effort(effort)
    challenge = P_STRING + service_id + seed + nonce + struct.pack(">I", effort)
    # BLAKE2b-32 必须设置 digest_size=4，不能截取 BLAKE2b-512 的前四字节。
    return int.from_bytes(hashlib.blake2b(challenge + solution, digest_size=4).digest(), "big")


def valid_effort(r: int, effort: int) -> bool:
    """检查 R × E <= 2^32 - 1；单独通过检查不代表 Equi-X 有效。"""
    if isinstance(r, bool) or not isinstance(r, int) or not 0 <= r <= UINT32_MAX:
        raise ValueError("R 必须是无符号 32 位整数")
    _effort(effort)
    return r * effort <= UINT32_MAX


def _increment_nonce(nonce: bytes) -> bytes:
    """按小端顺序递增 16 字节 nonce，并在 2^128 处回绕。"""
    _fixed_bytes(nonce, 16, "PoW nonce")
    return ((int.from_bytes(nonce, "little") + 1) & UINT128_MAX).to_bytes(16, "little")


def required_attempts(effort: int, service_id: bytes, seed: bytes,
                       max_attempts: int = 10000) -> int:
    """最多尝试 max_attempts 次随机候选值，不执行真正的 Equi-X。"""
    _effort(effort)
    _fixed_bytes(service_id, 32, "盲化服务身份")
    _fixed_bytes(seed, 32, "PoW 种子")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise ValueError("max_attempts 必须是正整数")
    nonce = os.urandom(16)
    for attempts in range(1, max_attempts + 1):
        candidate = os.urandom(16)  # 仅作统计替代，绝不是 Equi-X 解。
        if valid_effort(check_value(service_id, seed, nonce, effort, candidate), effort):
            return attempts
        nonce = _increment_nonce(nonce)
    raise RuntimeError("在 max_attempts 次尝试内未找到模拟候选值")
