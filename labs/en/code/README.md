# torlab — educational Tor client (English environment)

The `torlab` Python package accompanies the laboratories in *Anatomy of Tor*. It implements selected parts of the actual Tor protocol for teaching and uses only the **private laboratory network** described in [`../README.md`](../README.md). It is not a complete Tor client or an anonymity tool.

## Intended checks

From the **repository root**, with Python 3.11+, `pytest`, and `cryptography` installed:

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test
make -C labs/en test
```

The commands target the English package, not the Italian `labs/it/codice/torlab/` tree. These are local unit checks; they do **not** establish live interoperability or safety on the public Tor network.

## Package modules

| Module | Lab | Purpose |
|---|---:|---|
| `channel.py` | 1 | relay TLS connection, opening cells and relay identity |
| `cells.py` | 2 | fixed/variable-length cells and relay messages |
| `ntor.py` | 3 | ntor and ntor-v3 handshakes |
| `encryption.py`, `circuit.py` | 4 | layered encryption and circuit extension |
| `stream.py` | 5 | streams and SENDME |
| `directory.py` | 6 | consensus, certificates and microdescriptors |
| `path_selection.py` | 7 | weighted path selection |
| `onion.py` | 8 | onion v3 addresses and descriptors |
| `pow.py` | 9 | Blake2b threshold with **simulated** Equi-X solutions |
| `traffic.py` | 12 | interpreting decrypted TLS captures |
| `metrics.py` | 15 | consensus statistics |
| `simulation.py` | 19 | time-to-compromise simulation |
| `conversion.py` | App. B | key conversion and cross-certification |
| `laboratory.py` | support | locating private-network nodes and ports |

Other laboratories use separate scripts in `../lab/` where applicable. Cryptographic test vectors and signed documents remain unchanged byte-for-byte: they are not prose to translate. In particular, `pow.py` does **not** implement Equi-X; it simulates solutions to study the Blake2b layer.

## Scope and safety

This small client omits important protections, including complete congestion control, circuit rotation, padding, and traffic-analysis defenses. **Never use it to protect real people, carry sensitive traffic, or connect laboratory experiments to public relays.** Use up-to-date, officially maintained Tor or Arti software for actual privacy. A private Tor test network does not imply isolation from the host operating system.