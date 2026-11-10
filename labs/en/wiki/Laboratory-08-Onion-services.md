# Laboratory 8 — Finding and Reading an Onion-Service Descriptor

| | |
|---|---|
| **Chapter** | 14 — Onion Services |
| **Requires network?** | Yes |
| **Prerequisites** | Laboratories 1–6 |
| **Time** | About 4 hours to implement; about 2 minutes to rerun |
| **File** | `labs/en/code/torlab/onion.py` |

## What This Demonstrates

**Scope of this demonstration:** the example fetches a descriptor from the explicitly supplied final relay (`006e`); `download_descriptor()` does **not** compute or select the responsible HSDir. The ring algorithms (`responsible_hsdirs`, `relay_index`, `service_index`) are separate functions and are not validated by the successful three-hop download. The example supports ordinary, unrestricted descriptors; it does not implement restricted-discovery client credentials.

The onion address **encodes** the Ed25519 public identity key plus a checksum and version. An HSDir cannot normally recover the long-term identity from the blinded key alone, but anyone already knowing an address can derive blinded keys for the corresponding periods; this mechanism is not anonymity against a known-address observer.

A v3 `.onion` address **is derived from a public key**. Starting from that key, a client can derive the blinded key for the current time period, determine the service's positions on the HSDir ring, retrieve the descriptor, verify its signature, and decrypt its layers down to the introduction points.

The blinded key prevents an HSDir from trivially learning which long-term service identity it is storing. It changes from period to period, and someone who does not know the onion address cannot directly link it back to the service identity.

## Preparation

```bash
make -C labs/en/lab start
export PYTHONPATH=labs/en/code
```

The private network's onion service is node `009h`; its address is stored in `labs/en/lab/net/nodes/009h/hidden_service/hostname`.

## Run the Experiment

```bash
python3 - <<'EOF'
import calendar, time
from torlab.circuit import build, CircuitError
from torlab.laboratory import relay, NODES
from torlab.directory import parse_consensus, download
from torlab.onion import *

address = (NODES / "009h/hidden_service/hostname").read_text().strip()
print("address:", address)
A = key_from_address(address)
print("reconstructed from the address:", onion_address(A) == address)

c = parse_consensus(download(build([relay("000a")], cc=False),
                              "/tor/status-vote/current/consensus-microdesc", 1).decode())
ts = lambda k: calendar.timegm(time.strptime(" ".join(c.header[k]), "%Y-%m-%d %H:%M:%S"))
t = time_period_info(ts("valid-after"), ts("fresh-until") - ts("valid-after"), test_network=True)
print("period:", t.period, "duration (min):", t.duration_minutes)
Ap = blinded_key(A, t.period, t.duration_minutes)
print("blinded key:", Ap.hex()[:8] + "...")

# 1. negative control: one hop only
try:
    download_descriptor(Ap, [relay("006e")])
    raise AssertionError("one-hop descriptor request unexpectedly succeeded")
except CircuitError as e:
    print("with a one-hop circuit ->", e)

# 2. three hops, like a real client
desc = parse_descriptor(
    download_descriptor(Ap, [relay("003r"), relay("004r"), relay("006e")]), A, Ap)
print(f"lifetime {desc.duration_minutes} revision {desc.revision} "
      f"introduction points {len(desc.introduction_points)}")
for line in desc.inner_layer.splitlines()[:6]:
    print("  ", line[:66])
EOF
```

## Expected Output

**Illustrative output:** values such as the address, blinded key, period, revision, and HTTP error body vary between runs.

The one-hop HTTP `503` is the expected behavior in this lab setup, but is not a universal fixed response across versions or HSDirs. If the request unexpectedly succeeds, the negative check below raises an assertion instead of silently claiming a refusal.

```
address: jnl3qwwgchhbkammkqajwyuvcnt3shvaio53lnui7zr735hx4ab2slyd.onion
reconstructed from the address: True
period: 3729719 duration (min): 8
blinded key: 9fac5013...
with a one-hop circuit -> /tor/hs/3/n6xQEzASD31484ta7ZKChxNX14NTqcIyQlwXma5N9K0: HTTP/1.0 503 Rejecting single hop HS v3 descriptor request
lifetime 180 revision 14695413 introduction points 3
   create2-formats 2
   flow-control 1-2 31
   introduction-point AwAGfwAAARPvAhR4dPChvz+XuVSBXw7KiSkEsfo42wMgeF0
   onion-key ntor b0otE3LtQn7qnrGr8SKXxHCTOG9HSomwsQornrxIOCs=
   auth-key
   -----BEGIN ED25519 CERT-----
```

Your address, revision value, and keys will differ because the laboratory generates fresh service keys when the network is rebuilt.

How to interpret the result:

- `onion_address(key_from_address(x)) == x` demonstrates that the address is not an identifier allocated by a registry. It encodes the public key together with a checksum and version byte in base32.
- **`duration (min): 8`** reflects the private network's shortened HSDir period. Production parameters use much longer periods; the short interval exists so time-dependent behavior can be exercised in a laboratory.
- **`flow-control 1-2 31`** advertises congestion-control support and the same `sendme_inc = 31` observed in [Laboratory 5](Laboratory-05-Streams.md).
- The descriptor exposes three introduction points in this configuration.

## How the Original Failure Was Diagnosed

The first implementation could not retrieve the descriptor from **any** of the eight laboratory HSDirs. After testing all of them, HSDir choice was no longer a plausible explanation; the remaining possibilities were the blinded-key calculation or the request path.

The reference `tor` client was then asked to fetch the same descriptor through its control port (`HSFETCH`, followed by `GETINFO hs/client/desc/id/...`). Its certificate exposed the blinded key actually in use, which matched the implementation's result. That isolated the request as the fault: tor rejects v3 onion-descriptor requests arriving over a one-hop circuit. Using a normal three-hop circuit succeeded.

The general method matters more than the anecdote: when an experiment fails, identify an intermediate value that can be compared with a trusted reference implementation.

## An Honest Limitation

The private network has eight HSDirs and the service publishes to 2 × 4 = 8 of them—in other words, **all of them**. Successfully finding a descriptor therefore does not, by itself, prove the ring-position calculation is correct.

The client log records the HSDir actually queried, and that relay agrees with one of the positions predicted by the implementation for the relevant replica and period. That is consistent evidence, not a complete proof. Stronger validation would require more HSDirs or systematic comparison against tor over many periods.

## Automated Verification

The Italian historic `lab8` check needs an active private network; localized `test_onion.py` instead uses stored signed test vectors for address checksum, descriptor parsing, wrong-period rejection and the documented public-network time period. These are distinct checks.

The `lab8` check validates address reconstruction, the expected one-hop rejection, and successful descriptor decryption with at least one introduction point.

## Known Problems

A bare empty `authorized_clients/` directory is not proof of enabled restricted discovery or a universal cause of HTTP `400`. Inspect actual client authorization files and service logs; a descriptor needs valid `auth-client` entries when authorization is truly enabled.

| Symptom | Cause |
|---|---|
| `503 Rejecting single hop HS v3 descriptor request` | This is the intended negative control; use a three-hop circuit for the actual fetch. |
| `404` from every HSDir | The service may not have published yet, or the blinded key may have been derived for the wrong time period. |
| `400 Invalid HS descriptor` in service logs | Check the actual descriptor, authorization files and service logs. An empty `authorized_clients` directory alone does not establish the cause; see [Laboratory 13](Laboratory-13-Restricted-discovery.md). |

---

# Implementation, in Detail

`labs/en/code/torlab/onion.py` is roughly 250 lines and is one of the densest modules in the repository. It combines elliptic-curve arithmetic, time-period calculations, distributed-ring placement, and two encryption layers.

## The Address Is the Key

```python
def onion_address(key: bytes) -> str:
    """base32(PUBKEY | CHECKSUM | VERSION) + ".onion" (rend-spec, ONIONADDRESS)."""
    checksum = hashlib.sha3_256(b".onion checksum" + key + bytes([VERSION])).digest()[:2]
    return base64.b32encode(key + checksum + bytes([VERSION])).decode().lower() + ".onion"
```

A v3 `.onion` address contains 32 bytes of Ed25519 public key, a 2-byte checksum, and a 1-byte version value, all encoded as lower-case base32. Thirty-five bytes become 56 address characters before the `.onion` suffix.

There is no central registry assigning names: the address is cryptographically derived from the key. The checksum is not an authenticity mechanism against an attacker, since anyone can recompute it; it protects primarily against transcription errors. The `".onion checksum"` prefix also provides domain separation.

## The Blinding Factor

```python
def blinding_factor(A: bytes, period: int, duration_minutes: int) -> int:
    n = b"key-blind" + struct.pack(">QQ", period, duration_minutes)
    h = bytearray(hashlib.sha3_256(b"Derive temporary signing key\x00" + A + BASE_STR + n).digest())
    h[0] &= 248                                    # "clamping" as for Ed25519
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")


def blinded_key(A: bytes, period: int, duration_minutes: int) -> bytes:
    """A' = h·A: the service public key for a given period."""
    return _encode_point(_multiply(blinding_factor(A, period, duration_minutes), _decode_point(A)))
```

This is the mechanism that changes the public identity presented to HSDirs for each time period.

The nonce `N` includes the time-period number and duration as two 8-byte values. Changing the period changes `N`, therefore the derived scalar and blinded key. HSDirs storing today's descriptor do not automatically see the same long-term identity tomorrow unless they already know the onion address.

The `"Derive temporary signing key"` domain string ends with a zero byte, corresponding to the specification's encoding, and keeps this SHA3-256 use distinct from unrelated hash operations.

The three bit operations implement Ed25519 scalar **clamping**:

| Operation | Effect | Purpose |
|---|---|---|
| `h[0] &= 248` | Clears the low three bits | Makes the scalar a multiple of 8 |
| `h[31] &= 63` | Clears the top bit | Keeps the scalar in the required range |
| `h[31] |= 64` | Sets bit 254 | Enforces the required high-bit structure |

**`int.from_bytes(h, "little")`** is also easy to get wrong. Ed25519 uses little-endian scalar encoding, unlike many Tor protocol fields. An endian error produces a perfectly plausible but incorrect blinded key, typically resulting only in repeated descriptor lookup failures.

`_multiply` implements scalar multiplication for this educational client. The hand-written curve arithmetic follows the formulas referenced by the source material and is suitable for a teaching environment, **not** as production cryptographic code: it is neither optimized nor designed to resist timing side channels.

## Time Periods

`time_period_info()` computes a period number and a boolean about current versus previous SRV, **not the SRV value itself**. The demonstration neither reads shared-random values from consensus nor uses them in `responsible_hsdirs()`. Its test-network duration comes from voting-interval timing, not by parsing the `hsdir_interval` consensus parameter in this module. The historical eight-minute result is configuration-dependent.

```python
t = time_period_info(valid_after, voting_interval, test_network=True)
Ap = blinded_key(A, t.period, t.duration_minutes)
```

`time_period_info` calculates the time period from the voting interval and returns a flag for current-versus-previous SRV selection; fetching the actual SRV and constructing the HSDir ring would require additional steps.

Time periods and SRV phases are intentionally offset. A client must select the correct current or previous SRV depending on where it is within the rotation cycle. Using the wrong combination can produce a mathematically valid but temporally wrong HSDir ring.

The private network shortens the period to **8 minutes** so the behavior is observable during a laboratory session. `test_network=True` activates the corresponding test-network interpretation.

## Downloading and Decrypting

**Ring placement and retrieval are separate.** `responsible_hsdirs()` can compute candidate relay names when supplied the proper consensus HSDir Ed25519 identities, SRV, period, and settings. The `download_descriptor(blinded, path)` function does not call it: it sends `/tor/hs/3/<base64-blinded-key>` to the end of the caller-supplied path through `BEGIN_DIR`. The sample chooses `006e` explicitly; retrieval therefore does not prove any HSDir-ring calculation.

**Restricted discovery is not implemented here.** The second-layer decryption uses the blinded key and subcredential without an authorized client's x25519-derived descriptor cookie. Real restricted discovery needs the `auth-client` entry and client credentials; see [Laboratory 13](Laboratory-13-Restricted-discovery.md). Claiming that this code can decrypt authorization-protected descriptors would be incorrect.

**Security checks in the code:** `parse_descriptor()` verifies that the type-08 certificate is bound to, and signed by, the expected blinded key, checks the descriptor signature and enforces the `descriptor-lifetime` bounds (30–720 minutes). Certificate expiration is checked with `check_expiration=True`, which a client working with current data must use; the default is `False` because the laboratory's archived descriptors have already expired. The decoder does not compare `revision-counter` with descriptors already cached: that is the client's job. `key_from_address()` rejects with `ValueError` any address that is not 56 Base32 characters with a correct version and checksum.

```python
d = download_descriptor(Ap, [relay("003r"), relay("004r"), relay("006e")])
desc = parse_descriptor(d, A, Ap)
```

The actual `download_descriptor` method constructs a `BEGIN_DIR` circuit to the explicitly supplied last hop and requests the base64-encoded blinded key; it performs no ring lookup.

**A three-hop circuit is required.** An HSDir rejects a one-hop v3 descriptor request with `503 Rejecting single hop HS v3 descriptor request`. Accepting such a request would expose the requester's network address to the directory relay. This differs from the public consensus case in [Laboratory 6](Laboratory-06-Directory.md), where a one-hop directory circuit is appropriate.

`parse_descriptor` then performs three operations in order:

1. Verify that the descriptor signing-key certificate was issued under the **expected blinded key** derived locally from the onion address.
2. Verify the descriptor signature.
3. Decrypt the outer and inner layers.

The first check is essential: trusting a blinded identity merely because the descriptor states it would let the object authenticate itself.

The two descriptor layers serve different purposes: the outer layer can be decrypted by anyone knowing the onion address, while in restricted discovery the inner layer additionally requires an authorized client's descriptor cookie. **This educational parser does not implement that credential flow.** See [Laboratory 13](Laboratory-13-Restricted-discovery.md).

## Why the Debugging Method Matters

When every HSDir returned failure, the implementation compared an intermediate cryptographic value—the blinded key—with the one observed from the reference tor client. Because those values matched, the error could be isolated to transport/request behavior rather than curve arithmetic.

That approach generalizes: **when a protocol experiment fails, find an intermediate checkpoint and compare it with a trusted implementation**. The laboratory's tor client and ControlPort provide many such checkpoints.

## An Honest Limitation of This Laboratory

Because all eight laboratory HSDirs receive the service descriptor, successful retrieval does not establish that the ring-selection algorithm is fully correct. The client log provides one cross-check: the actual HSDir chosen by tor should be among those predicted for the same replica and period. A more convincing experiment would use substantially more HSDirs or compare many periods systematically.

## What You Need to Know to Make It Work

- The service must have **started and published** its descriptor; after a network restart this can take some time.
- If every HSDir returns `404`, first suspect the **period calculation**. Comparing adjacent periods can help diagnose an off-by-one timing error in the laboratory.
- A `400 Invalid HS descriptor` requires examining the real descriptor, client-authorization files and logs; do not presume a merely empty directory caused the failure. See [Laboratory 13](Laboratory-13-Restricted-discovery.md).
- The service address lives at `labs/en/lab/net/nodes/009h/hidden_service/hostname` and changes whenever the private network is regenerated.

## Where These Formulas Come From

| In the code | In the specification |
|---|---|
| Onion-address encoding | rend-spec, *Encoding onion addresses* |
| Blinding factor and clamping | rend-spec, *Appendix A: Signature scheme with key blinding* |
| Time periods and SRV | rend-spec, *Publishing shared random values* |
| HSDir ring placement | rend-spec, *Generating and publishing hidden service descriptors* |
| Descriptor layers | rend-spec, *Hidden service descriptors: encryption format* |
