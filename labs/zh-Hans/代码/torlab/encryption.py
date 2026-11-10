# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 4：洋葱式分层加密与 tor1 relay cell 加密。

规范依据：tor-spec 中 Relay cells（Recognized、Digest）与 Routing relay cells。
每一跳的每个方向都有独立的 AES-128-CTR 密码器及运行 SHA-1 摘要，
两者的状态均跨连续 cell 保留。
仅允许在本书私有实验网络中运行。
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .cells import CELL_BODY_LEN, RelayMessage, encode_relay, decode_relay
from .ntor import CircuitKeys

POS_DIGEST = slice(5, 9)       # 明文消息体中 Digest 字段的位置
POS_RECOGNIZED = slice(1, 3)


def _aes_ctr(key: bytes):
    # IV 为零；CTR 计数器会在整个电路生命周期中跨 cell 持续推进。
    return Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()


def _without_digest(body: bytes) -> bytes:
    return body[:5] + bytes(4) + body[9:]


@dataclass
class Direction:
    """一跳中一个方向的状态：AES 密钥流与运行摘要。"""
    cipher: object
    digest: "hashlib._Hash"

    @classmethod
    def new(cls, key: bytes, digest_seed: bytes) -> "Direction":
        if len(key) != 16 or len(digest_seed) != 20:
            raise CellError("AES-128 需要 16 字节密钥和 20 字节的摘要种子")
        d = hashlib.sha1()
        d.update(digest_seed)
        return cls(_aes_ctr(key), d)

    def apply(self, data: bytes) -> bytes:
        """CTR 模式下加密与解密相同：与密钥流进行 XOR。"""
        if len(data) != CELL_BODY_LEN:
            raise CellError("tor1 RELAY 信元体必须恰好为 509 字节")
        return self.cipher.update(data)

    def sign(self, body: bytes) -> bytes:
        """将 Digest 清零后把 cell 纳入运行摘要，再写入摘要前四字节。"""
        if len(body) != CELL_BODY_LEN:
            raise CellError("tor1 RELAY 信元体必须恰好为 509 字节")
        self.digest.update(_without_digest(body))
        return body[:5] + self.digest.digest()[:4] + body[9:]

    def recognizes(self, body: bytes) -> bool:
        """Recognized 为零且摘要正确时，才确认本跳是目标并更新状态。"""
        if len(body) != CELL_BODY_LEN:
            raise CellError("tor1 RELAY 信元体必须恰好为 509 字节")
        if body[POS_RECOGNIZED] != b"\x00\x00":
            return False
        candidate = self.digest.copy()
        candidate.update(_without_digest(body))
        if not hmac.compare_digest(candidate.digest()[:4], body[POS_DIGEST]):
            return False                      # Recognized 假阳性：忽略
        self.digest = candidate
        return True


@dataclass
class Hop:
    """客户端与中继针对某条电路某一跳共享的状态。"""
    forward: Direction
    backward: Direction

    @classmethod
    def from_keys(cls, k: CircuitKeys) -> "Hop":
        return cls(Direction.new(k.Kf, k.Df), Direction.new(k.Kb, k.Db))


class CellError(Exception):
    pass


@dataclass
class ClientCircuitCrypto:
    """客户端侧：知道每一跳的密钥。"""
    hops: list[Hop] = field(default_factory=list)

    def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
        """为 `destination` 跳点准备 RELAY 消息体（0 为第一跳）。"""
        if not self.hops:
            raise CellError("电路尚未建立任何跳点")
        d = len(self.hops) - 1 if destination is None else destination
        if not isinstance(d, int) or not 0 <= d < len(self.hops):
            raise CellError("目标跳点索引无效")
        body = self.hops[d].forward.sign(encode_relay(msg))
        for i in range(d, -1, -1):             # 从最内层向外层依次加密
            body = self.hops[i].forward.apply(body)
        return body

    def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
        """逐层解密入站 cell，直到某一跳能够识别它。"""
        if len(body) != CELL_BODY_LEN:
            raise CellError("tor1 RELAY 信元体必须恰好为 509 字节")
        if not self.hops:
            raise CellError("电路尚未建立任何跳点")
        for i, hop in enumerate(self.hops):
            body = hop.backward.apply(body)
            if hop.backward.recognizes(body):
                return i, decode_relay(body)
        raise CellError("没有任何跳点能够识别该 cell：应关闭电路")


@dataclass
class RelayHop:
    """中继侧（用于测试）：只知道本跳的密钥。"""
    hop: Hop

    def from_client(self, body: bytes) -> tuple[bool, bytes]:
        body = self.hop.forward.apply(body)
        return self.hop.forward.recognizes(body), body

    def to_client(self, msg: RelayMessage) -> bytes:
        return self.hop.backward.apply(self.hop.backward.sign(encode_relay(msg)))

    def forward_to_client(self, body: bytes) -> bytes:
        return self.hop.backward.apply(body)
