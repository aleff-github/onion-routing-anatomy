# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratory 4 — the onion: tor1 encryption of relay cells.

References: tor-spec, "Relay cells" (Recognized, Digest) and "Routing relay cells".
Each hop has, in each direction, an AES-128-CTR cipher and a running SHA-1 digest;
both retain state from one cell to the next.
Teaching module: use only on the book's private laboratory network.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .cells import CELL_BODY_LEN, RelayMessage, encode_relay, decode_relay
from .ntor import CircuitKeys

POS_DIGEST = slice(5, 9)       # bytes of the Digest field in the plaintext body
POS_RECOGNIZED = slice(1, 3)


def _aes_ctr(key: bytes):
    # Zero IV: the counter continues from cell to cell for the entire circuit lifetime.
    return Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()


def _without_digest(body: bytes) -> bytes:
    return body[:5] + bytes(4) + body[9:]


@dataclass
class Direction:
    """State for one direction of one hop: AES stream and running digest."""
    cipher: object
    digest: "hashlib._Hash"

    @classmethod
    def new(cls, key: bytes, digest_seed: bytes) -> "Direction":
        if len(key) != 16 or len(digest_seed) != 20:
            raise CellError("AES-128 requires a 16-byte key and a 20-byte digest seed")
        d = hashlib.sha1()
        d.update(digest_seed)
        return cls(_aes_ctr(key), d)

    def apply(self, data: bytes) -> bytes:
        """Encryption and decryption are identical in CTR mode: XOR with the keystream."""
        if len(data) != CELL_BODY_LEN:
            raise CellError("a tor1 RELAY cell body must contain exactly 509 bytes")
        return self.cipher.update(data)

    def sign(self, body: bytes) -> bytes:
        """Update the digest with the cell (Digest set to zero) and write the first 4 bytes."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("a tor1 RELAY cell body must contain exactly 509 bytes")
        self.digest.update(_without_digest(body))
        return body[:5] + self.digest.digest()[:4] + body[9:]

    def recognizes(self, body: bytes) -> bool:
        """Recognized is zero and the digest is correct; update state only if this hop owns the cell."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("a tor1 RELAY cell body must contain exactly 509 bytes")
        if body[POS_RECOGNIZED] != b"\x00\x00":
            return False
        candidate = self.digest.copy()
        candidate.update(_without_digest(body))
        if not hmac.compare_digest(candidate.digest()[:4], body[POS_DIGEST]):
            return False                      # false positive for Recognized: ignore
        self.digest = candidate
        return True


@dataclass
class Hop:
    """State shared by client and relay for one circuit hop."""
    forward: Direction
    backward: Direction

    @classmethod
    def from_keys(cls, k: CircuitKeys) -> "Hop":
        return cls(Direction.new(k.Kf, k.Df), Direction.new(k.Kb, k.Db))


class CellError(Exception):
    pass


@dataclass
class ClientCircuitCrypto:
    """Client side: knows the keys for every hop."""
    hops: list[Hop] = field(default_factory=list)

    def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
        """Prepare a RELAY cell body for hop `destination` (0 = first)."""
        if not self.hops:
            raise CellError("circuit contains no hops")
        d = len(self.hops) - 1 if destination is None else destination
        if not isinstance(d, int) or not 0 <= d < len(self.hops):
            raise CellError("invalid destination hop index")
        body = self.hops[d].forward.sign(encode_relay(msg))
        for i in range(d, -1, -1):             # layers from innermost to outermost
            body = self.hops[i].forward.apply(body)
        return body

    def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
        """Remove layers from an incoming cell until one hop recognizes it."""
        if len(body) != CELL_BODY_LEN:
            raise CellError("a tor1 RELAY cell body must contain exactly 509 bytes")
        if not self.hops:
            raise CellError("circuit contains no hops")
        for i, hop in enumerate(self.hops):
            body = hop.backward.apply(body)
            if hop.backward.recognizes(body):
                return i, decode_relay(body)
        raise CellError("cell not recognized by any hop: close the circuit")


@dataclass
class RelayHop:
    """Relay side (for tests): knows only the keys for its own hop."""
    hop: Hop

    def from_client(self, body: bytes) -> tuple[bool, bytes]:
        body = self.hop.forward.apply(body)
        return self.hop.forward.recognizes(body), body

    def to_client(self, msg: RelayMessage) -> bytes:
        return self.hop.backward.apply(self.hop.backward.sign(encode_relay(msg)))

    def forward_to_client(self, body: bytes) -> bytes:
        return self.hop.backward.apply(body)
