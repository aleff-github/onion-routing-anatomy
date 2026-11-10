# Laboratory 6 — Downloading and Verifying the Consensus

| | |
|---|---|
| **Chapter** | 12 — The Directory System |
| **Requires network?** | Yes |
| **Prerequisites** | Laboratories 1–5 |
| **Time** | About 3 hours to implement; about one minute to rerun |
| **File** | `labs/en/code/torlab/directory.py` |

## What This Demonstrates

This laboratory examines the directory trust model and demonstrates individual cryptographic checks on a private network. Directory authorities sign a consensus, and the SHA-256 digest of each microdescriptor is carried in the consensus. The teaching verifier illustrates those steps but does not establish the full trust chain on its own.

Just as importantly, the laboratory proves that verification **fails when it should**: changing a bandwidth value in the signed part of a consensus makes its previously matching signatures fail.

## Preparation

```bash
make -C labs/en/lab start
export PYTHONPATH=labs/en/code
```

## Run the Experiment

```bash
python3 - <<'EOF'
import base64
from torlab.circuit import build
from torlab.laboratory import relay
from torlab.directory import *

# a ONE-hop circuit to the authority, without congestion control:
# Tor permits this non-anonymous directory access, but not all directory requests are one hop
circ = build([relay("000a")], cc=False)
text = download(circ, "/tor/status-vote/current/consensus-microdesc", 1).decode()
c = parse_consensus(text)
print(f"consensus: {len(text)} byte; {' '.join(c.header['valid-after'])}"
      f" -> {' '.join(c.header['fresh-until'])}")

cert = parse_certificates(download(circ, "/tor/keys/all", 3).decode())
print(f"method {c.header['consensus-method'][0]}; signatures {len(c.signatures)}; certificates {len(cert)}")
for r in c.relay[:2]:
    print(f"  {r.name} {r.ip}:{r.orport} w={r.bandwidth} flag={sorted(r.flag)[:4]}...")

valid, required, _ = verify_consensus(c, cert, 3)
assert valid >= required, "not enough signatures matching the provided test certificates"
print(f"valid signatures: {valid} (required: {required})")

# negative control: change one digit in any bandwidth value in the
# live consensus: test-network bandwidth measurements change, so hard-coding one
# a hard-coded value (for example "Bandwidth=4096") would make replace a no-op when that value
# would be misleading and could make the negative check appear to never fail.
import re
bandwidth = re.search(r"Bandwidth=(\d+)", text)
assert bandwidth is not None, "missing Bandwidth field"
altered_text = text.replace(bandwidth.group(0), f"Bandwidth={int(bandwidth.group(1)) + 1}", 1)
assert altered_text != text
modified = parse_consensus(altered_text)
negative_valid = verify_consensus(modified, cert, 3)[0]
assert negative_valid == 0, "modified document passed signature check"
print("modified consensus -> valid signatures:", negative_valid)

dig = "-".join(base64.b64encode(r.microdesc).decode().rstrip("=") for r in c.relay)
md = parse_microdescriptors(download(circ, f"/tor/micro/d/{dig}", 5).decode())
assert all(r.microdesc in md for r in c.relay), "missing requested microdescriptor"
print(f"microdescriptors: {len(md)}; match consensus m entries: "
      f"{all(r.microdesc in md for r in c.relay)}")
EOF
```

## Expected Output

`valid-after` to `fresh-until` is the *freshness* interval, while `valid-until` separately marks expiry. The private-network timestamps shown are illustrative, not universal validity durations.

**Security boundary:** this teaching verifier checks consensus RSA signatures using certificates downloaded from the same directory service. It does **not** validate authority certificates against pinned, trusted identity keys, verify certificate certifications or cross-certifications, check expiration, or enforce consensus time validity. A majority of matching RSA signatures is therefore **not proof that the document comes from trusted Tor authorities**. The complete trust chain remains outside the implemented exercise.

The following is a historical, illustrative private-network run; its values are not guaranteed.

```
consensus: 5961 byte; 2026-09-24 16:01:20 -> 2026-09-24 16:01:40
method 36; signatures 3; certificates 3
  test000a 127.0.0.1:5100 w=20 flag=['Authority', 'Fast', 'Guard', 'HSDir']...
  test005r 127.0.0.1:5105 w=4096 flag=['Fast', 'Guard', 'HSDir', 'Running']...
valid signatures: 3 (required: 2)
modified consensus -> valid signatures: 0
microdescriptors: 8; match consensus m lines: True
```

How to interpret it:

- The private network uses short voting periods. Do not confuse `valid-after` → `fresh-until` (freshness) with `valid-after` → `valid-until` (validity). The displayed dates illustrate the configuration, not a universal 40-second lifetime.
- **3 valid signatures from 3 authorities; 2 were sufficient.** The acceptance rule is a strict majority.
- **`valid signatures: 0`** after modifying the consensus is the most important result on this page. A verifier that never fails does not verify anything.
- Each downloaded microdescriptor's SHA-256 digest matches the corresponding `m` line in the consensus, showing a digest linkage, but not full trust anchoring.

## The Detail That Usually Causes Trouble

The signature does not cover the entire file: the signed text ends immediately after the literal `directory-signature ` keyword and its trailing space. Files downloaded from **CollecTor** may also begin with an annotation such as `@type network-status-microdesc-consensus-3 1.0`, which is **not part of the signed document**.

If that annotation is included in the digest, every signature fails. The resulting symptom looks cryptographic even though the actual mistake is document framing. `signed_text` therefore begins from the real network-status document, and a regression test fixes this behavior.

## Offline Check Using Repository Fixtures

The earlier CollecTor example referenced `fonti/collector` files which are **not present in this repository**. A reproducible test instead uses the signed private-network snapshot checked into `labs/en/code/torlab/test/data/`. Actual public-network CollecTor data and matching historical authority certificates must be acquired separately. The 3/2 result below checks consistency with supplied fixture certificates, not trusted identities.

```python
from pathlib import Path
from torlab.directory import parse_consensus, parse_certificates, verify_consensus
fixture = Path("labs/en/code/torlab/test/data")
consensus = parse_consensus((fixture / "consensus-microdesc.txt").read_text())
certificates = parse_certificates((fixture / "authority-certificates.txt").read_text())
matching, required, _ = verify_consensus(consensus, certificates, 3)
assert (matching, required) == (3, 2)  # consistency check, NOT trusted roots
```

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test/test_directory.py
```

## Automated Verification

The Italian `lab6` checker targets the private network. The localized `test_directory.py` exercises saved fixture documents. They do not verify trusted authority roots.

## Known Problems

| Symptom | Cause |
|---|---|
| `RELAY_END NOTDIRECTORY` or HTTP `503` | A relay may not offer a directory service; `NOTDIRECTORY` is a relay-level error and `503` is an HTTP status from a directory service. Inspect the actual response. |
| `valid signatures: 0` on a separately downloaded public consensus | Check the CollecTor `@type` annotation, the presence of matching historical certificates, and correct document framing; the files must first be downloaded independently. |
| HTTP `503` from the directory service | Inspect the returned HTTP status and choose a working private directory authority or cache; a non-directory relay may instead send `END NOTDIRECTORY`. |
| The consensus contains fewer relays than expected | It may have been fetched during a consensus transition on the private network. Retry after roughly half a minute. |

---

# Implementation, in Detail

`labs/en/code/torlab/directory.py` is roughly 230 lines. It performs four tasks: downloading directory documents through a circuit, parsing them, verifying their signatures, and binding microdescriptors back to the consensus.

## Downloading Through a Circuit

```python
def download(circ: Circuit, path: str, stream_id: int) -> bytes:
    """HTTP/1.0 GET against the final hop's directory service over BEGIN_DIR."""
    s = Stream(circ, stream_id)
    circ.send(RelayMessage(RelayCommand.BEGIN_DIR, stream_id, b""))
    _, msg = s._next()
    if msg.command != RelayCommand.CONNECTED:
        raise CircuitError(f"BEGIN_DIR rejected: {msg.command}")
    s.send(f"GET {path} HTTP/1.0\r\n\r\n".encode())
    response = s.receive_all()
    header, _, body = response.partition(b"\r\n\r\n")
    state = header.split(b"\r\n")[0]
    if b" 200 " not in state:
        raise CircuitError(f"{path}: {state.decode()}")
    return body
```

`BEGIN_DIR` uses the last hop's directory service, not an external TCP destination. Clients MUST send an empty body; relays MUST ignore the received body. The relay MUST send an empty `CONNECTED` body on success, while clients MUST ignore that response body. A relay without a directory service may respond with `RELAY_END NOTDIRECTORY`, rather than HTTP `503`.

A one-hop circuit here is an explicitly **non-anonymous** directory-access example. Tor permits one hop for non-anonymous directory requests but does not require every directory request to follow this pattern; onion service descriptors have different anonymity needs.

```python
circ = build([relay("000a")], cc=False)
```

This **one-hop circuit** without congestion-control negotiation is one allowed non-anonymous directory-access pattern. It is a teaching configuration; it does not describe every directory request made by Tor.

> This shortcut applies to public directory documents such as the consensus, **not** to onion-service descriptors. For those, requester anonymity matters and HSDirs reject inappropriate one-hop access patterns; see [Laboratory 8](Laboratory-08-Onion-services.md).

## The netdoc Format

This `items` implementation is a teaching parser for expected netdocs, not a complete hardened validator of potentially malformed documents. For example, truncated PEM objects may raise an exception.

```python
def items(text: str) -> list[Item]:
    """Split a netdoc-format document into items (dir-spec, netdoc)."""
    output, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line:
            continue
        keyword, *arguments = line.split(" ")
        object_text = None
        if i < len(lines) and lines[i].startswith("-----BEGIN "):
            j = i
            while not lines[j].startswith("-----END "):
                j += 1
            object_text = "\n".join(lines[i:j + 1]).encode()
            i = j + 1
        output.append(Item(keyword, arguments, object_text))
    return output
```

Tor directory documents—consensuses, votes, relay descriptors, microdescriptors and authority certificates—share a simple meta-format: a keyword, space-separated arguments, and optionally a PEM-like object on following lines. A small generic `items` parser can therefore serve as the base for all document-specific parsers.

`parse_consensus` then behaves like a straightforward state machine: an `r` line starts a relay entry, and `s`, `w`, `p`, and `m` lines fill in its attributes. The `r` line includes nickname, identity, address and port; `w` carries bandwidth information; `m` carries the microdescriptor digest.

## The Signature Boundary, and the Byte Everyone Gets Wrong

The correct code extracts bytes starting with `network-status-version ` to skip the CollecTor `@type` annotation, and stops after the first `directory-signature ` marker. Matching an RSA digest does **not** validate the authority certificate's origin or validity.

```python
def signed_text(text: str) -> bytes:
    """Part of the consensus covered by signatures: from "network-status-version" through the
    space after "directory-signature" (dir-spec, "directory-signature").

    Files downloaded from CollecTor begin with an annotation line, "@type ...",
    which is not part of the signed document and must be discarded.
    """
    start = text.index("network-status-version ")
    pos = text.index("\ndirectory-signature ") + len("\ndirectory-signature ")
    return text[start:pos].encode()
```

The signature **does not cover the entire document**. It covers the text through the literal `directory-signature` keyword and the following space. One extra or missing byte changes the digest.

This becomes especially important with **CollecTor**, whose archived files may prepend an annotation:

```
@type network-status-microdesc-consensus-3 1.0
network-status-version 3 microdesc
```

That `@type` line is metadata from the archive, **not part of the signed network-status document**. If it is included, all signatures fail together. That “everything failed at once” pattern is a useful clue that framing is wrong rather than one authority key.

```python
def verify_signature(consensus: Consensus, signature: Signature, cert: AuthorityCertificate) -> bool:
    """The signature is RSA PKCS#1 v1.5 over the digest *without* the algorithm identifier:
    recover the digest from the signature and compare it with the computed digest."""
    h = hashlib.sha256 if signature.algorithm == "sha256" else hashlib.sha1
    expected = h(signed_text(consensus.text)).digest()
    try:
        recovered = cert.signing_key.recover_data_from_signature(
            signature.signature, padding.PKCS1v15(), None)
    except Exception:
        return False
    return recovered == expected
```

`recover_data_from_signature` with algorithm `None` recovers the digest embedded by Tor's RSA signature format without requiring a normal ASN.1 DigestInfo structure. That matches the historical Tor signing construction described by the directory specification. A generic high-level `verify()` call expecting a conventional encoded algorithm identifier can therefore reject otherwise valid Tor signatures.

The hash algorithm comes from the signature metadata itself. Modern consensus signatures use SHA-256, while the parser remains capable of handling formats that identify SHA-1 as long as the network format permits it.

A constant-time comparison is unnecessary here because both the expected digest and the signed document are public. By contrast, the ntor-v3 `AUTH` comparison in Laboratory 3 involves secret-derived authentication state and uses `hmac.compare_digest`.

## Digest Linkage and Trust Boundaries

The correct chain starts with **pretrusted authority identity keys**, verified authority signing certificates and valid consensus signatures, then continues through the SHA-256 digest in each `m` entry to the microdescriptor and its `ntor-onion-key`. This implementation demonstrates only the latter links and an RSA-signature consistency check; it must not be used as a secure public-network bootstrap.

```text
pretrusted authority keys → validated certificates → signed consensus → SHA-256 `m` → microdescriptor → `ntor-onion-key`
```

## The Negative Control

This explicit assertion proves the test has really modified the signed bytes and that the simplified RSA checker detects the modification. It is not an authority trust-anchor test.

```python
import re
bandwidth = re.search(r"Bandwidth=(\d+)", text)
assert bandwidth is not None, "missing Bandwidth field"
altered_text = text.replace(bandwidth.group(0), f"Bandwidth={int(bandwidth.group(1)) + 1}", 1)
assert altered_text != text
altered = parse_consensus(altered_text)
assert verify_consensus(altered, cert, 3)[0] == 0
```

A verifier that never fails proves nothing. Modifying one numerical value and observing the valid-signature count fall to zero distinguishes a functioning verifier from code that simply returns success.

The test deliberately does **not** hard-code a value such as `Bandwidth=4096`. Private-network measured bandwidth values vary. If a hard-coded value is absent, `replace` would change nothing and the negative test could silently pass without testing anything. This live example and the Italian `lab6` verifier find the bandwidth value dynamically. In contrast, the separate bundled fixed-fixture unit test may safely replace its known `Bandwidth=4096` value.

## What You Need to Know to Make It Work

- **Not every relay is a directory cache.** Non-directory relays may return `END NOTDIRECTORY`, while a directory HTTP server can return an error status such as `503`. In the private lab use an available authority (`000a`, `001a`, or `002a`).
- The private-network consensus is intentionally short-lived. Fetching during a transition can produce confusing intermediate observations; retry after the next vote.
- The microdescriptor consensus and the full consensus are **different document flavors** with different relay-line formats, even though signature verification follows the same principles.
- The microdescriptor endpoint is `/tor/micro/d/<digests separated by ->`, using base64 digests without trailing `=` padding.

## Where These Rules Come From

| In the code | In the specification |
|---|---|
| `BEGIN_DIR` | tor-spec, *Opening streams and transmitting data* |
| netdoc format | dir-spec, *netdoc document meta-format* |
| Signed-text boundary | dir-spec, *Signing documents* |
| Authority certificates | dir-spec, *Directory authority key certificates* |
| Microdescriptors | dir-spec, *Computing microdescriptors* |
