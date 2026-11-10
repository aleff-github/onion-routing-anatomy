# torlab — Educational Tor client (English edition)

This small, readable Python package accompanies the book's **private** Tor laboratories. It is a teaching implementation, **not** a production Tor client or an anonymity tool. Do not use it to protect real identities or run its interactive experiments on the public Tor network; use Tor Browser or Arti for real-world use. The private network setup is documented in [`../../lab/`](../../lab/README.md).

| Laboratory | Chapter | Module(s) | Scope |
|---|---|---|---|
| 1 | 07 | `channel.py` | TLS channel; VERSIONS, CERTS, NETINFO and identity checks |
| 2 | 08 | `cells.py` | Fixed and variable cells, including relay framing |
| 3 | 09 | `ntor.py` | CREATE_FAST, ntor/ntor-v3; CREATE2/CREATED2 and EXTEND2 |
| 4 | 10 | `encryption.py`, `circuit.py` | Layered encryption, digests and circuit construction |
| 5 | 11 | `stream.py` | BEGIN/DATA/END, SENDME and stream flow control |
| 6 | 12 | `directory.py` | Consensus, relay data, certificates and microdescriptors |
| 7 | 13 | `path_selection.py` | Consensus-weighted guard/middle/exit selection |
| 8 | 14 | `onion.py` | v3 onion addresses, blinding, HSDirs and descriptors |
| 9 | 15 | `pow.py` | Blake2b acceptance threshold: **simulation without Equi-X** |
| 12 | 20 | `traffic.py` | Read cells from an already decrypted TLS trace |
| 15 | 24 | `metrics.py` | Network statistics and illustrative user estimates |
| 19 | 29 | `simulation.py` | Simplified TorPS-style compromise model |
| Appendix B | B | `conversion.py` | Montgomery/Edwards conversion and cross-certification |
| Support | 19 | `laboratory.py` | Private-network relay identities and keys |

### Running the tests

From the **repository root**, install the project's Python test dependencies in an isolated environment, then use the following commands. They operate on local fixtures; do not direct network experiments to public relays.

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test
```

PowerShell equivalent:

```powershell
$env:PYTHONPATH = "labs/en/code"
python -m pytest -q labs/en/code/torlab/test
```

The data under `test/data/` includes cryptographic documents and capture fixtures: **do not translate or alter their bytes** to localize the lab.

### Protocol boundaries and source data

- **Lab 7:** the selector handles consensus bandwidth weights (including `bwweightscale`), relay IDs and IPv4 `/16` separation, but not all relay-family rules, exit policies, IPv6 constraints or Tor's persistent-guard logic. Lab test consensus data must not be mistaken for a dated public consensus.
- **Lab 8:** certificate signatures and descriptor encryption are explored with historical fixtures. The parser defaults to `check_expiration=False` for archived data; callers handling live data must validate expiry and the authenticated directory independently. Client authorization/restricted discovery and complete introduction-point checks are not implemented.
- **Lab 9:** `required_attempts()` draws **random 16-byte stand-ins**, not Equi-X proofs. It stops after `max_attempts` (default **10,000**) and can raise `RuntimeError`. A successful Blake2b threshold check is **not** a valid Tor PoW.
- **Labs 12, 15 and 19:** traffic, metrics and simulation exercises use their own recorded or dated inputs. Public-network statistical examples require separately verified historical datasets; the private fixture cannot substitute for them. The simulation is not a quantitative anonymity guarantee.

Source code, constants, protocol field names and cryptographic test vectors retain their original bytes and identifiers across translations.
