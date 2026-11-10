# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratory 2 — encode and decode Tor cells.

References: tor-spec, "Cells (messages on channels)", "Relay cells",
"Message lengths", "Negotiating versions with VERSIONS cells".
Teaching module: readability is more important than performance.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import IntEnum

CELL_BODY_LEN = 509          # bytes in the body of a fixed-length cell
RELAY_HEADER_LEN = 11        # header of a relay message (traditional format)
RELAY_DATA_MAX = CELL_BODY_LEN - RELAY_HEADER_LEN   # 498


class CellCommand(IntEnum):
    """Values of the Command field (tor-spec, cell-packet-format)."""
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    VERSIONS = 7
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11
    PADDING_NEGOTIATE = 12
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132


class RelayCommand(IntEnum):
    """Values of the Relay command field (tor-spec, relay-cells)."""
    BEGIN = 1
    DATA = 2
    END = 3
    CONNECTED = 4
    SENDME = 5
    EXTEND = 6
    EXTENDED = 7
    TRUNCATE = 8
    TRUNCATED = 9
    DROP = 10
    RESOLVE = 11
    RESOLVED = 12
    BEGIN_DIR = 13
    EXTEND2 = 14
    EXTENDED2 = 15
    CONFLUX_LINK = 19
    CONFLUX_LINKED = 20
    CONFLUX_LINKED_ACK = 21
    CONFLUX_SWITCH = 22
    ESTABLISH_INTRO = 32
    ESTABLISH_RENDEZVOUS = 33
    INTRODUCE1 = 34
    INTRODUCE2 = 35
    RENDEZVOUS1 = 36
    RENDEZVOUS2 = 37
    INTRO_ESTABLISHED = 38
    RENDEZVOUS_ESTABLISHED = 39
    INTRODUCE_ACK = 40
    PADDING_NEGOTIATE = 41
    PADDING_NEGOTIATED = 42
    XOFF = 43
    XON = 44


class CellError(ValueError):
    """Malformed cell or cell not permitted by the protocol."""


def circid_len(version: int) -> int:
    """CircID length in bytes: 2 through link protocol 3, 4 from version 4 onward."""
    return 2 if version < 4 else 4


def is_variable_length(command: int) -> bool:
    """VERSIONS (7) and all commands >= 128 are variable-length."""
    return command == CellCommand.VERSIONS or command >= 128


@dataclass
class Cell:
    circ_id: int
    command: int
    body: bytes = b""


def encode(cell: Cell, version: int) -> bytes:
    """Serialize a cell for a channel using link protocol `version`.

    VERSIONS cells are always encoded with version 0 (a 2-byte CircID),
    because the link-protocol version has not yet been negotiated when they are sent.
    """
    if cell.command == CellCommand.VERSIONS:
        version = 0
    n = circid_len(version)
    if not 0 <= cell.circ_id < 1 << (8 * n):
        raise CellError(f"CircID {cell.circ_id:#x} does not fit in {n} bytes")
    # Match CircID to the command class required by tor-spec.
    if cell.command in (
        CellCommand.PADDING, CellCommand.VERSIONS, CellCommand.NETINFO, CellCommand.VPADDING,
        CellCommand.CERTS, CellCommand.AUTH_CHALLENGE, CellCommand.AUTHENTICATE, CellCommand.AUTHORIZE,
    ) and cell.circ_id != 0:
        raise CellError("this cell requires a zero CircID")
    if cell.command in (
        CellCommand.CREATE, CellCommand.CREATED, CellCommand.RELAY, CellCommand.DESTROY,
        CellCommand.CREATE_FAST, CellCommand.CREATED_FAST, CellCommand.RELAY_EARLY,
        CellCommand.CREATE2, CellCommand.CREATED2, CellCommand.PADDING_NEGOTIATE,
    ) and cell.circ_id == 0:
        raise CellError("this cell requires a nonzero CircID")
    header = cell.circ_id.to_bytes(n, "big") + bytes([cell.command])
    if is_variable_length(cell.command):
        if len(cell.body) > 0xFFFF:
            raise CellError("body too long for a variable-length cell")
        return header + struct.pack(">H", len(cell.body)) + cell.body
    if len(cell.body) > CELL_BODY_LEN:
        raise CellError(f"body of {len(cell.body)} bytes > {CELL_BODY_LEN}")
    # Zero-pad to CELL_BODY_LEN (tor-spec, body-padding).
    return header + cell.body.ljust(CELL_BODY_LEN, b"\x00")


def decode(buffer: bytes, version: int) -> tuple[Cell, bytes] | None:
    """Extract the first cell from `buffer`.

    Return (cell, remaining_bytes), or None if the buffer does not yet contain
    a complete cell: TLS data can arrive in fragments of arbitrary size.
    """
    n = circid_len(version)
    if len(buffer) < n + 1:
        return None
    circ_id = int.from_bytes(buffer[:n], "big")
    command = buffer[n]
    if is_variable_length(command):
        if len(buffer) < n + 3:
            return None
        (length,) = struct.unpack(">H", buffer[n + 1:n + 3])
        end = n + 3 + length
        body_start = n + 3
    else:
        end = n + 1 + CELL_BODY_LEN
        body_start = n + 1
    if len(buffer) < end:
        return None
    return Cell(circ_id, command, buffer[body_start:end]), buffer[end:]


# --- VERSIONS -----------------------------------------------------------------

def versions_cell(versions: list[int]) -> Cell:
    """Build a VERSIONS cell from a list of 2-byte big-endian integers."""
    return Cell(0, CellCommand.VERSIONS, b"".join(struct.pack(">H", v) for v in versions))


def negotiate_version(ours: list[int], received_body: bytes) -> int:
    """Choose the highest mutually supported version (tor-spec, VERSIONS-cells)."""
    if len(received_body) % 2:
        raise CellError("VERSIONS with an odd number of bytes")
    theirs = {v for (v,) in struct.iter_unpack(">H", received_body)}
    common = set(ours) & theirs
    if not common:
        raise CellError("no common link-protocol version")
    return max(common)


# --- DESTROY ------------------------------------------------------------------

DESTROY_REASONS = ["NONE", "PROTOCOL", "INTERNAL", "REQUESTED", "HIBERNATING",
                  "RESOURCELIMIT", "CONNECTFAILED", "OR_IDENTITY", "CHANNEL_CLOSED",
                  "FINISHED", "TIMEOUT", "DESTROYED", "NOSUCHSERVICE"]


def destroy_cell(circ_id: int, reason: int = 0) -> Cell:
    """DESTROY: the body is a single reason byte; the specification recommends NONE (0)."""
    if circ_id == 0:
        raise CellError("DESTROY requires a nonzero CircID")
    return Cell(circ_id, CellCommand.DESTROY, bytes([reason]))


# --- Relay messages (traditional format, before CGO) ----------------------

@dataclass
class RelayMessage:
    command: int
    stream_id: int
    data: bytes = b""
    recognized: int = 0
    digest: bytes = b"\x00\x00\x00\x00"


def encode_relay(msg: RelayMessage, random_bytes=os.urandom) -> bytes:
    """Produce the plaintext 509-byte body of a RELAY cell.

    Padding: 4 zero bytes followed by random bytes (tor-spec, relay-cell-padding).
    The digest is computed separately (Chapter 10); this function uses the value in `msg`.
    """
    if len(msg.data) > RELAY_DATA_MAX:
        raise CellError(f"at most {RELAY_DATA_MAX} data bytes for cell")
    header = struct.pack(">BHH4sH", msg.command, msg.recognized,
                               msg.stream_id, msg.digest, len(msg.data))
    space = CELL_BODY_LEN - RELAY_HEADER_LEN - len(msg.data)
    padding = b"\x00" * min(4, space) + random_bytes(max(0, space - 4))
    return header + msg.data + padding


def decode_relay(body: bytes) -> RelayMessage:
    """Parse the *already decrypted* body of a RELAY cell."""
    if len(body) != CELL_BODY_LEN:
        raise CellError("a RELAY cell body is always 509 bytes")
    command, recognized, stream_id, digest, length = struct.unpack(
        ">BHH4sH", body[:RELAY_HEADER_LEN])
    if length > RELAY_DATA_MAX:
        raise CellError(f"Length field {length} > {RELAY_DATA_MAX}")
    data = body[RELAY_HEADER_LEN:RELAY_HEADER_LEN + length]
    return RelayMessage(command, stream_id, data, recognized, digest)


def describe(cell: Cell, version: int) -> str:
    """Human-readable cell representation for debugging."""
    try:
        name = CellCommand(cell.command).name
    except ValueError:
        name = f"UNKNOWN({cell.command})"
    w = 2 * circid_len(0 if cell.command == CellCommand.VERSIONS else version)
    return f"CircID=0x{cell.circ_id:0{w}x} {name} body={len(cell.body)} bytes"
