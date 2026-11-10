# Laboratories

Each language has its own self-contained environment with the same layout:

- `code/` — `torlab`, the small educational Tor client built chapter by chapter, with offline tests;
- `lab/` — Docker image (tor and Chutney built from pinned sources) and the private Tor network;
- `wiki/` — step-by-step guides for Laboratories 1–20;
- `data/` — instructions for the public historical data used by some laboratories (downloaded on request).

| Language | Path | Status |
|---|---|---|
| Italiano | [`it/`](it/) | **Validated**: 53/53 live checks on the private network and 14/14 for Laboratory 10 (obfs4 bridge), 28 October 2026 — see [`docs/it/validazione/`](../docs/it/validazione/) |
| English | [`en/`](en/) | Sources available; no live validation |
| Español | [`es/`](es/) | Sources available; no live validation |
| Русский | [`ru/`](ru/) | Sources available; no live validation |
| 简体中文 | [`zh-Hans/`](zh-Hans/) | Sources available; no live validation |

The book text refers to the Italian environment (`labs/it/...`). Quick start:

```bash
make -C labs/it test        # offline tests, no network
make -C labs/it immagine    # build the Docker image (tor + Chutney)
make -C labs/it avvia       # start the private network on 127.0.0.1
make verifica-lab           # rerun the laboratories live (from the repository root)
```

**Safety rules.** Every experiment runs on the private network or as an ordinary client:
never against public relays or real users (Tor Research Safety Board principles). All
listeners of the laboratory network are bound to `127.0.0.1`. The Chutney networks generate
private keys and node identities in `labs/*/lab/net/`: that directory is ignored by git and
must never be published.
