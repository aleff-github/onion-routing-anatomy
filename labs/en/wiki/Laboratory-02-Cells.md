# Laboratory 2 — Encoding and Decoding Cells

| | |
|---|---|
| **Chapter** | 8 — Cells: the Basic Format |
| **Requires network?** | No |
| **Prerequisites** | Python 3.11 or later |
| **Time** | 1–2 hours to implement; about 2 minutes to rerun |
| **Files** | `labs/en/code/torlab/cells.py`, `labs/en/code/torlab/test/test_cells.py` |

## What This Demonstrates

**514 bytes** applies to fixed cells for link protocol 4 and higher; version 3 uses a 2-byte CircID and 512-byte cells.

A Tor cell is a simple, rigid structure: 4 bytes of CircID, 1 command byte, and a 509-byte body—**514 bytes total**, regardless of what it carries. This uniformity prevents cell length from directly revealing its contents. Variable-length cells (`VERSIONS` and all commands >= 128) are the exception. `VERSIONS` always uses a 2-byte CircID because it is exchanged before the link-protocol version has been negotiated.

## Preparation

Nothing beyond the repository code is required:

```bash
cd /path/to/repository
export PYTHONPATH=labs/en/code
```

## Run the Experiment

```bash
python3 - <<'EOF'
from torlab.cells import *

# 1. a fixed-length cell
c = Cell(0x80000001, CellCommand.RELAY, b"\x01" * 509)
g = encode(c, 4)
print("length:", len(g), "| first 8 bytes:", g[:8].hex())

# 2. decode: return the cell and any remaining bytes
decoded_cell, remaining = decode(g, 4)
print("decoded:", hex(decoded_cell.circ_id), CellCommand(decoded_cell.command).name, "| remaining:", len(remaining))

# 3. a variable-length cell
print("VERSIONS:", encode(Cell(0, CellCommand.VERSIONS, b"\x00\x04\x00\x05"), 4).hex())

# 4. a relay message inside a cell body
m = RelayMessage(RelayCommand.BEGIN, 1, b"127.0.0.1:80\x00")
r = encode_relay(m)
print("relay message:", len(r), "byte | header:", r[:11].hex())
rit = decode_relay(r)
print("decoded:", RelayCommand(rit.command).name, rit.stream_id, rit.data)
EOF
```

## Expected Output

```
length: 514 | first 8 bytes: 8000000103010101
decoded: 0x80000001 RELAY | remaining: 0
VERSIONS: 000007000400040005
relay message: 509 byte | header: 010000000100000000000d
decoded: BEGIN 1 b'127.0.0.1:80\x00'
```

How to read it:

- `8000000103` is CircID `0x80000001` (the high bit is one because the circuit was created by us, the channel initiator) followed by command `3` (`RELAY`).
- The `VERSIONS` cell is `0000` (a **2-byte** CircID) + `07` (command) + `0004` (length) + `0004 0005` (offered versions 4 and 5).
- The relay-message header is `01` (`BEGIN`), `0000` (`Recognized`), `0001` (StreamID), `00000000` (Digest, still empty; Laboratory 4's encryption fills it), and `000d` (13 data bytes).

`Cell.command` and `RelayMessage.command` are integers. Convert them through `CellCommand(...)` and `RelayCommand(...)` to print symbolic names.

## Automated Verification

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test/test_cells.py
```

The seven tests cover both 512/514-byte fixed-cell formats, VERSIONS, fragmented input, version negotiation, a legal DESTROY reason 0 **and rejection of CircID 0**, relay messages of at most 498 data bytes and their padding.

The Italian verifier has a `lab2` function; the root `make verify-labs` is an English environment target, not a standalone execution of this named check. The command above runs the English `test_cells.py` functions only.

## Known Problems

None specific to the laboratory. It has no external dependencies: if it does not work, first check your Python installation and repository checkout.

---

# Implementation, in Detail

The entire laboratory lives in `labs/en/code/torlab/cells.py`, roughly 220 lines. Every later laboratory depends on it. A mistake here can surface three experiments later as a circuit that a relay closes without a useful explanation.

The function listings below are excerpts from the full `cells.py` module; its imports and auxiliary definitions are not repeated here.

## Constants

```python
CELL_BODY_LEN = 509          # bytes in the body of a fixed-length cell
RELAY_HEADER_LEN = 11        # relay-message header
RELAY_DATA_MAX = CELL_BODY_LEN - RELAY_HEADER_LEN   # 498
```

`RELAY_DATA_MAX` is not a literal constant copied from the specification; it is a **consequence** of the other two lengths. Expressing it as a subtraction rather than hard-coding `498` keeps the relationship visible if one of the formats changes. That possibility is not purely academic: CGO relay encryption (Proposal 359, already represented in tor's code) uses a different header, while Proposal 340 would separate messages from cells entirely.

Commands are represented as `IntEnum`, not plain `Enum`. That matters in a binary protocol: commands need to compare and pack as integers—`bytes([cell.command])` must work—while still having readable symbolic names.

```python
def circid_len(version):
    return 2 if version < 4 else 4

def is_variable_length(command):
    return command == CellCommand.VERSIONS or command >= 128
```

CircID width depends on the negotiated link-protocol version: 2 bytes through version 3, and 4 bytes from version 4 onward. Keeping that rule in a helper avoids scattering magic numbers throughout the module.

The “>= 128” rule is part of the protocol specification: the command's high bit signals a variable-length cell. `VERSIONS` (command 7) is the historical exception because it predates that convention.

## `encode`

```python
def encode(cell: Cell, version: int) -> bytes:
    """Serialize a cell for a channel using link protocol `version`.

    VERSIONS cells are always encoded with version 0 (a 2-byte CircID),
    because the link-protocol version has not yet been negotiated when they are sent.
    """
    if cell.command == CellCommand.VERSIONS:
        version = 0
    n = circid_len(version)
    if not 0 <= cell.circ_id < 1 << (8 * n):
        raise CellError(f"CircID {cell.circ_id:#x} does not fit in {n} byte")
    header = cell.circ_id.to_bytes(n, "big") + bytes([cell.command])
    if is_variable_length(cell.command):
        if len(cell.body) > 0xFFFF:
            raise CellError("body too long for a variable-length cell")
        return header + struct.pack(">H", len(cell.body)) + cell.body
    if len(cell.body) > CELL_BODY_LEN:
        raise CellError(f"body of {len(cell.body)} bytes > {CELL_BODY_LEN}")
    # Zero-pad to CELL_BODY_LEN (tor-spec, body-padding).
    return header + cell.body.ljust(CELL_BODY_LEN, b"\x00")
```

The first two lines are the special case that surprises most readers. `VERSIONS` is exchanged *before* the link version has been agreed, so its format cannot depend on that version. Forcing `version = 0` produces a 2-byte CircID, as the specification requires. It is the only cell whose format must be determined independently of version negotiation; otherwise negotiation could not begin.

`"big"` means network byte order, used for Tor's integer fields. Explicitly validating the CircID range is technically redundant because `to_bytes` would raise `OverflowError`, but the custom error explains which value failed and how many bytes were available—useful in an educational implementation.

The two cell families diverge here:

- **Variable-length:** write the 2-byte `Length` and then the body exactly as supplied. There is no fixed-size padding because the length is explicit.
- **Fixed-length:** zero-pad the body to **509 bytes**. The specification requires this, and receivers ignore the added bytes.

> Fixed-cell padding is link-level data, readable to the immediate TLS peer after decryption, but not to outside eavesdroppers. Relay-message padding remains under the onion encryption until it reaches the recognizing/decrypting hop.

## `decode`

**Incoming `VERSIONS` needs version 0:** before negotiating a link version, call `decode(buffer, 0)` so its CircID uses two bytes. Only after negotiation should you call `decode(buffer, negotiated_version)` for subsequent cells; passing 4 prematurely would parse the header incorrectly.

```python
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
```

This function is designed to be called whenever bytes arrive from a socket, even when the caller does not yet know whether a complete cell is present. It therefore has **three** separate completeness checks, exactly where a naïve parser tends to fail on real traffic:

1. Without CircID and command, the parser cannot even know which cell format applies.
2. A variable-length cell requires two more bytes before the body length is known.
3. Finally, the complete body must have arrived.

Returning `None` means “call me again when more bytes are available,” not “protocol error.” This keeps the caller simple:

```python
while True:
    result = decode(buffer, version)
    if result is None:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed before a complete cell")
        buffer += chunk
        continue
    cell, buffer = result
    ...
```

A TLS read may contain fragments or multiple cells; a maximum 16 KiB record could hold 31 complete 514-byte cells, but no fixed grouping is implied.

This educational client uses immutable `bytes` buffers and slices off consumed data on every call. A production implementation would use a circular or similarly efficient buffer to avoid repeatedly copying the remainder. At relay throughput, the difference matters.

## `negotiate_version`

```python
def negotiate_version(ours: list[int], received_body: bytes) -> int:
    """Choose the highest mutually supported version (tor-spec, VERSIONS-cells)."""
    if len(received_body) % 2:
        raise CellError("VERSIONS with an odd number of bytes")
    theirs = {v for (v,) in struct.iter_unpack(">H", received_body)}
    common = set(ours) & theirs
    if not common:
        raise CellError("no common link-protocol version")
    return max(common)
```

An odd-length body cannot be a list of 2-byte integers, so it is rejected rather than guessed at. The function then computes the intersection and chooses the **highest** common value, following the specification's rule.

A natural question is what prevents a **downgrade** in which an intermediary removes newer versions from the lists. This helper cannot detect that by itself. Protection comes from the surrounding channel protocol:

- The exchange already occurs inside TLS, and [Laboratory 1](Laboratory-01-Channel.md) binds the channel to the relay's identity through `CERTS`.
- When the initiator is itself a relay and authenticates, the `AUTHENTICATE` digest covers **all** bytes exchanged, including `VERSIONS`. Tampering would therefore be detected.

## `encode_relay`

```python
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
```

One `struct.pack` serializes all five header fields. The format `">BHH4sH"` can be read left to right exactly like the Chapter 8 diagram: command (1 byte), `Recognized` (2), StreamID (2), Digest (4 raw bytes, hence `4s`), and `Length` (2). Total: 11 bytes, equal to `RELAY_HEADER_LEN`.

The specification recommends (**SHOULD**) up to four zero bytes then random bytes; when fewer than four padding bytes are available, they are all zero. Padding does not by itself authenticate or recognize a relay message: `Recognized` and `Digest` must be checked.

| | Fixed-length cells | Relay messages |
|---|---|---|
| Padding | Zero bytes | Up to 4 zero bytes, then random if room |
| Who sees it in plaintext | Immediate TLS peer (not outsiders) | Hop that recognizes/decrypts the relay message |
| Purpose | Fill the fixed-size body | Keep unused relay-body contents unpredictable |

If relay-message padding were all zeroes, an adversary able to guess the actual payload would know the rest of the body as well, which interacts badly with authenticated `SENDME` construction from Proposal 289 ([Laboratory 5](Laboratory-05-Streams.md)). The specification recommends (**SHOULD**) up to four zero bytes then random bytes; when fewer than four padding bytes are available, they are all zero. Padding does not by itself authenticate or recognize a relay message: `Recognized` and `Digest` must be checked.

The `random_bytes` parameter exists solely for tests, allowing random bytes to be replaced by predictable values. Without dependency injection, tests could verify only total length. This is a broader design rule used throughout the repository: **inject nondeterminism instead of burying it inside the implementation**.

For the onion-layer recognition procedure, see [Laboratory 4](Laboratory-04-Encryption.md).

## Where These Formats Come From

Every implementation rule maps to the protocol specifications:

| In the code | In spec.torproject.org |
|---|---|
| Cell lengths and format | tor-spec, *Cells (messages on channels)* |
| Zero padding | tor-spec, *Padding fixed-length cell bodies* |
| `VERSIONS` and negotiation | tor-spec, *Negotiating versions with VERSIONS cells* |
| Relay-message header | tor-spec, *Relay cells* |
| 4 zeroes + random bytes | tor-spec, *Relay cells* (rationale: Proposal 289) |
| Command lists | tor-spec tables in *Cells* and *Relay cells* |
