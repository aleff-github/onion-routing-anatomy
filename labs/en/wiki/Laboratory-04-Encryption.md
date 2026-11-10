# Laboratory 4 — Layered Encryption and a Three-Hop Circuit

| | |
|---|---|
| **Chapter** | 10 — Layered Encryption |
| **Requires network?** | Yes |
| **Prerequisites** | Laboratories 1–3 |
| **Time** | About 3 hours to implement; about one minute to rerun |
| **Files** | `labs/en/code/torlab/encryption.py`, `labs/en/code/torlab/circuit.py` |

## What This Demonstrates

This laboratory shows how the “onion” actually works: one encryption key and one running digest **for every hop and for each direction**, with the client wrapping every message in as many layers as there are hops. A middle relay cannot tell in advance whether a received value is intended for it or is merely another layer to remove. It attempts recognition; if recognition fails, it forwards the result.

Most importantly, this laboratory builds a real circuit incrementally, one hop at a time, all the way to an exit.

## Preparation

```bash
make -C labs/en/lab start
export PYTHONPATH=labs/en/code
```

## Run the Experiment

```bash
python3 - <<'EOF'
import time
from torlab.cells import CellCommand
from torlab.circuit import build
from torlab.laboratory import relay

circ = build([relay("003r"), relay("004r"), relay("006e")])
print("hops:", len(circ.crypto.hops), "| extensions requested from the exit:", circ.exit_extensions)

# link padding, which did not appear in Laboratory 1
circ.channel.sock.settimeout(12)
seen, t = 0, time.time()
try:
    while time.time() - t < 12:
        if circ.channel.receive().command == CellCommand.PADDING:
            seen += 1
except TimeoutError:
    pass
print(f"PADDING cells received in 12 s: {seen}")
EOF
```

## Expected Output

```
hops: 3 | extensions requested from the exit: [(2, b'\x1f')]
PADDING cells received in 12 s: 3
```

How to interpret it:

- `build` opens the channel to the guard, creates the first hop using ntor-v3, then extends twice. The `EXTEND2` message uses **StreamID zero** because it is a circuit-control message. It travels inside `RELAY_EARLY`, not `RELAY`; this is the mechanism that limits circuit extension to eight such cells ([Laboratory 17](Laboratory-17-Relay-early.md)).
- This example requests congestion control **only from its final hop**. `[(2, b'\x1f')]` is the exit's reply, with `sendme_inc = 31`.
- **Link padding is configuration- and timing-dependent.** Extending beyond the guard may make the channel eligible for link padding under the relevant configuration; the sample count is illustrative, not a promise of one or more `PADDING` cells within twelve seconds.

## The Core of the Laboratory

The onion itself is just two loops:

```python
def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
    d = len(self.hops) - 1 if destination is None else destination
    body = self.hops[d].forward.sign(encode_relay(msg))
    for i in range(d, -1, -1):
        body = self.hops[i].forward.apply(body)
    return body

def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
    for i, hop in enumerate(self.hops):
        body = hop.backward.apply(body)
        if hop.backward.recognizes(body):
            return i, decode_relay(body)
    raise CellError("cell not recognized by any hop: close the circuit")
```

`recognizes` is more subtle than it looks. It requires the `Recognized` field to be zero **and** the running digest to match. If digest verification fails, the digest state must remain unchanged; otherwise, a false positive would permanently desynchronize the circuit. The implementation therefore checks a copy (`self.digest.copy()`) and adopts it only when verification succeeds.

These snippets are excerpts of methods in `ClientCircuitCrypto` and `Circuit`; imports, types and state are defined in the full Python modules.

## The Limitation of In-Memory Tests

`test_encryption.py` constructs a simulated three-relay circuit and verifies that each hop recognizes only its own cells, that middle relays see apparently random bytes, that tampering is detected at the destination, and that AES-CTR is malleable.

Those tests have a serious limitation: simulated client and relays use **the same implementation**. If both sides updated the digest in the same incorrect order, the tests could still pass. The strongest verification is interoperability with the independent `tor` implementation, which is what this laboratory exercises.

## Automated Verification

The original Italian `lab4` verifier belongs to `scripts/verify_labs.py`; it is not an executable named `lab4` in this localized environment. The localized `test_encryption.py` provides offline simulated-relay unit tests; the command above is a separate manual interoperability experiment on the private Chutney network. Padding can be absent in a finite observation interval.

## Known Problems

| Symptom | Cause |
|---|---|
| `cell not recognized by any hop: close the circuit` | Digest state is desynchronized, often because it was updated even when recognition failed. |
| `PADDING cells received: 0` | Padding is randomized. It can happen occasionally; if it happens consistently, check that the circuit really has three hops. |
| Extension fails with `DESTROY` | Examine circuit logs and the reason code; an identity mismatch is one possibility, not proof that an Ed25519 specifier was missing. |

---

# Implementation, in Detail

Two modules are involved: `labs/en/code/torlab/encryption.py` (the onion mechanism itself, about 115 lines) and `labs/en/code/torlab/circuit.py` (channel, CircID, and hops combined, also about 115 lines).

## What a `Direction` Stores

```python
POS_DIGEST = slice(5, 9)
POS_RECOGNIZED = slice(1, 3)

def _aes_ctr(key):
    return Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()

def _without_digest(body):
    return body[:5] + bytes(4) + body[9:]
```

**The IV is zero**, and this is not a shortcut. In Tor, the CTR state continues from cell to cell for the life of the circuit, so the keystream does not restart for each cell. Reinitializing the cipher for every cell would repeat the keystream and catastrophically weaken encryption, even though the implementation might appear to work.

```python
@dataclass
class Direction:
    cipher: object
    digest: "hashlib._Hash"
```

A `Direction` groups two pieces of state that must advance consistently: the AES-CTR cipher state and the running digest. They are conceptually separate in the specification but operationally coupled. Each hop has two directions, forward and backward, so a three-hop circuit maintains six `Direction` objects.

## Encrypting and Decrypting Are the Same Primitive

```python
def apply(self, data):
    return self.cipher.update(data)
```

In CTR mode, encryption and decryption are both XOR with the keystream. That symmetry is why a middle relay can “remove a layer” without applying a different primitive.

It also means AES-CTR is **malleable**: flipping a bit in ciphertext flips the corresponding plaintext bit. The running digest is what detects this kind of modification; Appendix B of the book demonstrates the property explicitly.

## The Digest Is Not Per-Cell

```python
def sign(self, body):
    self.digest.update(_without_digest(body))
    return body[:5] + self.digest.digest()[:4] + body[9:]
```

The running digest covers **only relay cells originated by or addressed to this hop in that direction**, not forwarded cells intended for other hops. `update` accumulates state, so every accepted message depends on the preceding history.

The prescribed sequence is: clear the Digest field using `_without_digest`, update the running hash with that representation, take the first four bytes of the result, and write those bytes into the Digest field. The receiver performs the same calculation.

A practical consequence follows: **losing or reordering a relay cell permanently desynchronizes the running state**. Tor does not attempt to recover from that situation; the circuit is closed.

Ordinary circuits use SHA-1 for this running digest, whereas onion-service circuits use SHA3-256. The use of SHA-1 here is tied to this protocol construction rather than ordinary collision-resistance requirements.

## Recognition, and the Copy That Protects the Circuit

```python
def recognizes(self, body):
    if body[POS_RECOGNIZED] != b"\x00\x00":
        return False
    candidate = self.digest.copy()
    candidate.update(_without_digest(body))
    if candidate.digest()[:4] != body[POS_DIGEST]:
        return False                 # false positive: state unchanged
    self.digest = candidate
    return True
```

This is the module's most delicate operation.

The first filter is `Recognized`: if it is not zero, this relay is not the intended recipient and no digest state is touched.

Yet two zero bytes can occur by chance, approximately once in 65,536 random values. The digest then provides the second test. If the implementation updated the real digest state before discovering that the Digest field was wrong, a false positive would corrupt every later verification.

Using `copy()` and committing the state only after successful verification makes failed recognition **side-effect free**. This is exactly the behavior required to keep the circuit synchronized.

## The Two Onion Loops

```python
def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
    d = len(self.hops) - 1 if destination is None else destination
    body = self.hops[d].forward.sign(encode_relay(msg))
    for i in range(d, -1, -1):
        body = self.hops[i].forward.apply(body)
    return body

def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
    for i, hop in enumerate(self.hops):
        body = hop.backward.apply(body)
        if hop.backward.recognizes(body):
            return i, decode_relay(body)
    raise CellError("cell not recognized by any hop: close the circuit")
```

Outbound traffic is signed using the destination hop's digest, then wrapped from the innermost destination layer outward. Inbound traffic removes layers from the outside inward and attempts recognition after each layer.

Notice that `decrypt` does not know in advance which hop produced the message. It discovers the sender by progressively removing layers and checking recognition, mirroring the protocol's relay behavior.

## Extending a Circuit

```python
def extend(self, r: RelayInfo, extensions=()) -> list[tuple[int, bytes]]:
    st, hd = ntor3_client_start(r.id_ed, r.ntor, encode_extensions(list(extensions)))
    body = extend2_body("127.0.0.1", r.port, r.id_rsa, r.id_ed, HTYPE_NTOR_V3, hd)
    self.send(RelayMessage(RelayCommand.EXTEND2, 0, body), early=True)
    hop, msg = self.receive()
    if msg.command != RelayCommand.EXTENDED2:
        raise CircuitError(f"extension failed: {RelayCommand(msg.command).name}")
    sm, k = ntor3_client_finish(st, hdata_created2(msg.data))
    self.crypto.hops.append(Hop.from_keys(CircuitKeys.from_stream(k)))
    return decode_extensions(sm)
```

Three details cause confusing failures when implemented incorrectly:

- **StreamID zero:** `EXTEND2` controls the circuit rather than an application stream.
- **`RELAY_EARLY`, not `RELAY`:** circuit-extension requests use the special cell type whose finite allowance limits extension depth ([Laboratory 17](Laboratory-17-Relay-early.md)).
- **Relay identities:** this example supplies both RSA and Ed25519 link specifiers to `EXTEND2`. The specification does **not** universally require an Ed25519 identity in every `EXTEND2`; when a relay knows it from the consensus, it SHOULD check it. A missing Ed25519 specifier alone does not necessarily cause `DESTROY`.

In this example congestion control is requested **only at the final hop**: the `(1, b"")` extension is sent to the exit rather than the middle relay.

## The Limitation of In-Memory Tests

`test_encryption.py` is useful for checking invariants, but both simulated sides use the same code. Protocol tests that reuse one implementation at both endpoints can miss symmetric bugs. Independent interoperability with `tor` is therefore an essential validation layer.

## What You Need to Know to Make It Work

- Circuit keys come from the ntor key stream: 20+20 digest bytes (`Df`, `Db`) and 16+16 encryption-key bytes (`Kf`, `Kb`), 72 bytes total. Their ordering matters.
- A direction's **initial digest state** is seeded with `Df` or `Db`, not with an empty hash.
- A `Direction` object cannot be reused across circuits because it contains advancing CTR state.
- If `cell not recognized by any hop: close the circuit` appears for a message that should be yours, inspect every branch where the running digest might have been advanced when it should not have been.

## Where These Rules Come From

| In the code | In the specification |
|---|---|
| Recognized and Digest fields | tor-spec, *Relay cells* |
| Digest calculation | tor-spec, *Calculating the 'Digest' field* |
| Relay routing behavior | tor-spec, *Routing relay cells* |
| Circuit keys | tor-spec, *Setting circuit keys* |
| EXTEND2 and link specifiers | tor-spec, *Creating circuits* |
