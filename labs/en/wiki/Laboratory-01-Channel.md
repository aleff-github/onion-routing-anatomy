# Laboratory 1 — Opening a Verified Channel

| | |
|---|---|
| **Chapter** | 7 — Channels: TLS and the Link Handshake |
| **Requires network?** | Yes |
| **Prerequisites** | Laboratory 2 (`cells.py`); `cryptography` |
| **Time** | 2–3 hours to implement; about one minute to rerun |
| **File** | `labs/en/code/torlab/channel.py` |

**Sequence note:** this first network laboratory uses the cell encoder from Laboratory 2 (`cells.py`). The module is already included in this repository; when implementing the project from scratch, study or implement that parser before running the channel example.

## What This Demonstrates

A relay's TLS certificate is **not proof of its identity**. It is self-signed, and anyone can produce one. The relay demonstrates its identity *inside* the channel, using the `CERTS` cell. This binds its Ed25519 identity to a signing key and that key to the fingerprint of the TLS certificate in use. Verifying the entire chain, and then comparing its identity with the one we intended to connect to, is what prevents an intermediary from impersonating our chosen relay.

## Preparation

```bash
make -C labs/en/lab start      # if the network is not already running
export PYTHONPATH=labs/en/code
```

## Run the Experiment

```bash
python3 - <<'EOF'
from torlab.channel import open_channel, identity_from_file

expected = identity_from_file("labs/en/lab/net/nodes/003r/fingerprint-ed25519")
c = open_channel("127.0.0.1", 5103, expected_identity=expected)
print(c.version, c.ed_identity.hex()[:16] + "...", c.netinfo, c.auth_methods)
for r in c.registry:
    print("  ", r)

# and now the negative control: the right kind of relay, but another identity
try:
    open_channel("127.0.0.1", 5104, expected_identity=expected)
except Exception as e:
    print("port 5104 with 003r identity ->", e)
EOF
```

## Expected Output

```
5 785d3199f21d20ad... Netinfo(timestamp=1790265613, peer_address='127.0.0.1', my_addresses=['127.0.0.1']) [3]
   TLS TLSv1.3 TLS_AES_256_GCM_SHA384
   <- VERSIONS (6 byte)
   <- CERTS (1456 byte)
   <- AUTH_CHALLENGE (36 byte)
   <- NETINFO (509 byte)
   -> NETINFO: channel open

port 5104 with 003r identity -> the relay has a different identity from the expected one
```

How to interpret the result:

- **`5`** is the negotiated link-protocol version. We offer versions 4 and 5, as Arti does; version 3 is no longer useful here.
- Your relay's hexadecimal identity **will differ from the example**. Fresh laboratory network initialization produces new node keys. Likewise, the length of the `CERTS` cell depends on its certificates and may differ.
- **`[3]`** represents authentication methods the relay would accept from *another relay*. We are acting as a client and do not authenticate ourselves. If a client authenticated, it could acquire a stable, recognizable identity across channels—the opposite of our objective.
- In `NETINFO`, the relay provides its time and the address it sees us coming from. Our reply deliberately supplies **a zero timestamp and no addresses**: a client does not reveal its clock time or its own addresses.
- **In the historical example** the fresh channel has no `PADDING` cells. Channel padding depends on circuit use, negotiation, and network parameters; merely opening a one-hop channel does not make padding obligatory. The later multi-hop example in [Laboratory 4](Laboratory-04-Encryption.md) can illustrate it, but a particular run may vary.

## The Essential Negative Control

The final output line is the most important part of the experiment. We connect to relay `004r` while declaring that we expect `003r`; our code correctly refuses the connection. An implementation that verifies certificate signatures and expiry dates but **fails to compare the resulting identity with the expected identity** could pass every positive test while providing no protection against relay substitution.

## Automated Verification

The Italian verifier contains a `lab1` routine that checks `003r`, `006e`, and `000a` and rejects the wrong identity. That routine is **not** a standalone `lab1` command in the English environment. Here, run the private network and the manual example above, and check the local code tests separately with `PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test/test_channel.py`. `make -C labs/en/lab verify` checks the active Chutney topology; it does not replace the laboratory example or certify the entire experiment.

The network-free tests in `test_channel.py` build a valid certificate chain using two newly generated keys, then corrupt it in each way required by the specification: invalid signature, uncertified signing key, different TLS fingerprint, expired certificate, and duplicate certificate type. Every invalid variant must be rejected.

## Known Problems

| Symptom | Cause |
|---|---|
| `ConnectionRefusedError` on port 5103 | The network is not running; check `make -C labs/en/lab status`. |
| `the relay has a different identity from the expected one` on the correct port | You restarted from fresh keys but kept an old fingerprint. Read `fingerprint-ed25519` again. |
| `unexpected cell during the handshake` | You are talking to something other than a Tor relay, perhaps the wrong port. |

## Where to Go Next

The channel is the foundation of everything else. [Laboratory 3](Laboratory-03-Handshake.md) builds circuits on top of it.

---

# Implementation, in Detail

`labs/en/code/torlab/channel.py` is approximately 260 lines long. It opens a TLS connection, verifies the peer's identity, and returns a `Channel` object through which later laboratories send cells.

The source fragments below are taken from `labs/en/code/torlab/channel.py`. They use imports and constants defined elsewhere in that module; execute the complete file rather than treating each fragment as a standalone script.

## Why TLS Alone Is Not Enough

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

To someone experienced in security, these three lines may seem like a serious mistake. In this context, they are not.

A Tor relay's TLS certificate is **self-signed** and contains no verifiable domain name. No certificate authority authenticates relays, and ordinary CA validation would not make sense here. Enabling Python's standard CA validation would cause every relay connection to fail. Identity verification happens **inside** the channel through `CERTS`, whose certificate chain is bound to the actual TLS session through the fingerprint of its certificate.

Put differently: TLS provides encryption; Tor supplies relay authentication.

> Copying these three lines into a normal HTTPS client **would disable its certificate-based protections**. They are safe in this narrowly defined Tor-channel example only because the code immediately verifies the complete Tor certificate chain and checks it against a relay identity chosen in advance.

```python
if os.environ.get("SSLKEYLOGFILE"):
    ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
```

This follows the convention used by browsers: if `SSLKEYLOGFILE` is set, the TLS library exports session secrets so Wireshark can decrypt a packet capture. This is what makes [Laboratory 12](Laboratory-12-Traffic.md) possible. Importantly, we decrypt **our own** traffic using keys voluntarily exported by our own program.

```python
source = (source_address, 0) if source_address else None
```

The `source_address` argument selects the local source address—for example `127.0.0.2`. It is used by the anti-DoS demonstration in [Laboratory 9](Laboratory-09-DoS.md) to vary the source IP for controlled runs.

## The Certificate Chain

```python
def verify_responder_identity(certificates: dict[int, bytes], cert_tls_der: bytes) -> bytes:
    """Apply the rules in "Authenticating the responder from its CERTS".

    Return KP_relayid_ed (32 bytes) if the chain
        Ed25519 identity -> signing key -> TLS certificate
    is valid; otherwise raise ChannelError.
    """
    try:
        id_v_sign = decode_ed_certificate(certificates[CERT_IDENTITY_V_SIGNING])
        sign_v_tls = decode_ed_certificate(certificates[CERT_SIGNING_V_TLS_CERT])
    except KeyError as e:
        raise ChannelError(f"missing certificate of type {e.args[0]}") from None

    identity = id_v_sign.signing_key
    if identity is None:
        raise ChannelError("IDENTITY_V_SIGNING without a signing key")
    id_v_sign.verify_signature(identity)                      # self-signed by the identity key
    signing_key = id_v_sign.certified_key             # KP_relaysign_ed
    sign_v_tls.verify_signature(signing_key)
    if sign_v_tls.certified_key != hashlib.sha256(cert_tls_der).digest():
        raise ChannelError("SIGNING_V_TLS_CERT does not match the received TLS certificate")
    for c in (id_v_sign, sign_v_tls):
        if c.expired():
            raise ChannelError(f"certificate of type {c.kind} expired")
    return identity
```

This function performs several separate authentication checks:

| Component | What it does | What it prevents |
|---|---|---|
| Type 4 | Binds the relay identity to its signing key | Arbitrary signing keys impersonating the relay |
| `signing_key` | Reads **who signed** from extension 4 | Inferring an identity instead of extracting it from the certificate |
| Self-signature | Checks that the type-4 certificate is internally consistent | Little by itself: anyone can self-sign a certificate |
| Type 5 | Binds the signing key to the TLS certificate | A certificate chain unrelated to the current session |
| SHA-256 fingerprint | Binds everything to **this connection** | An intermediary presenting an honest relay's certificates on its own TLS session |
| Expiration dates | Reject obsolete certificates | Acceptance of retired signing keys |

The most important check is the comparison with the TLS certificate fingerprint. Without it, the chain could be genuine but useless: it would prove that a relay with the claimed identity *exists*, not that we are currently communicating with it.

**Identity is not a normal certificate field here:** it is the key that signed the certificate, carried in extension 4. The certificate effectively says, “I, X, certify key Y.” X must be read from that extension rather than inferred from where the certificate came from.

## The Check Missing From That Function

```python
identity = verify_responder_identity(certificates, cert_tls)
if expected_identity is not None and identity != expected_identity:
    raise ChannelError("the relay has a different identity from the expected one")
```

A valid certificate chain proves we are communicating with **a** relay; it does not prove that it is **the relay we selected**. Comparing the identity against the expected identity is the step that turns authentication into authentication of the intended peer. That is the check we deliberately make fail by connecting to port 5104 using `003r`'s fingerprint.

Passing `expected_identity` is essential: the function permits `None` for callers that intentionally perform no pinned-identity comparison, but the secure demonstration above supplies the identity of the intended relay.

An implementation that verifies signatures and expiration but omits this comparison passes positive tests yet provides no protection against substitution.

## The Handshake Loop

```python
while netinfo is None:
    cell, buffer = _read(sock, buffer, version)
    registry.append(f"<- {CellCommand(cell.command).name} ({len(cell.body)} byte)")
    if cell.command == CellCommand.VERSIONS:
        if version:
            continue                                  # subsequent VERSIONS cells: ignore
        version = negotiate_version(SUPPORTED_VERSIONS, cell.body)
    elif cell.command == CellCommand.VPADDING:
        continue
    elif cell.command == CellCommand.CERTS:
        certificates = decode_certs(cell.body)
    elif cell.command == CellCommand.AUTH_CHALLENGE:
        (n,) = struct.unpack(">H", cell.body[32:34])
        methods = [m for (m,) in struct.iter_unpack(">H", cell.body[34:34 + 2 * n])]
    elif cell.command == CellCommand.NETINFO:
        netinfo = decode_netinfo(cell.body)
    else:
        raise ChannelError(f"unexpected cell during the handshake: {cell.command}")
```

- **The loop ends when `NETINFO` arrives**, not after some hard-coded number of cells. The handshake ends when the relay sends the required message; intermediate cells may vary.
- A second `VERSIONS` cell is **ignored**, as required by the specification. Without that `continue`, another cell could unexpectedly renegotiate the version midway through the handshake.
- We parse `AUTH_CHALLENGE` only to record the proposed methods. We are a client and will not authenticate: that would give the relay a stable identity to recognize across channels.
- The final branch is especially important: **anything not explicitly allowed is an error**. `VPADDING` can be silently discarded because the specification permits it at any point. Any other unexpected handshake cell is rejected. An `else: pass` would seem more tolerant but would silently accept arbitrary sequences.

Immediately after the loop comes an easily forgotten check:

```python
if certificates is None:
    raise ChannelError("NETINFO received before CERTS")
```

Without it, a malicious peer could send `NETINFO` immediately and bypass authentication. The loop would finish, leaving `verify_responder_identity` to receive `None`.

## Our NETINFO

```python
channel.send(client_netinfo_cell(host))
```

Our `NETINFO` reply carries **a zero timestamp and no address of our own**. This is not a laboratory shortcut: a real Tor client behaves the same way. Advertising the time on our own clock could expose a relatively stable clock skew; advertising our addresses could reveal information a client should not disclose.

## What You Need to Know to Make It Work

- **Fingerprints change whenever you reinitialize the network.** `identity_from_file` reads `labs/en/lab/net/nodes/<node>/fingerprint-ed25519`. Its contents are `<name> <base64-key>` without trailing `=` padding; the code restores the padding before decoding.
- **The port is always `5100 + node number`.**
- This channel does **not** send padding or actively keep the connection alive. An idle channel may be closed by the relay after a few minutes (Chapter 7).
- A newly opened channel does not receive `PADDING`. The relay enables padding only after a channel has carried a **complete** circuit, one extending beyond that relay, or user traffic. In `channelpadding.c`, these correspond to `CHANNEL_USED_FOR_FULL_CIRCS` and `CHANNEL_USED_FOR_USER_TRAFFIC`. Our one-hop circuits do not qualify; padding appears in [Laboratory 4](Laboratory-04-Encryption.md). Once that threshold is met, padding may begin **before** the first application data: this is governed by the consensus parameter `nf_pad_before_usage`, whose default is 1.

## Where These Rules Come From

| In the code | In the specification |
|---|---|
| Handshake sequence | tor-spec, *Negotiating and initializing channels* |
| Certificate verification | tor-spec, *Authenticating the responder from its CERTS* |
| Ed25519 certificate format | cert-spec, *Tor Ed25519 Certificates* |
| Types 4 and 5, extension 4 | cert-spec, *Certificate types (CERT_TYPE field)* |
| NETINFO contents | tor-spec, *NETINFO cells* |
| AUTH_CHALLENGE format | tor-spec, *AUTH_CHALLENGE cells* |
