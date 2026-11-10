# Laboratory Environment — English

This directory is the English teaching environment for *Anatomy of Tor*.

It maintains its own English files, scripts and documentation, rather than sharing the Italian source tree. Protocol identifiers, test vectors and expected protocol behavior remain unchanged. **Source-directory separation is not container or network isolation:** the EN, RU and ZH-CN laboratory Makefiles reuse the Docker image `torbook-lab:latest`, the container `torbook-network` and overlapping host ports through `--network host`. Never run these networks simultaneously.

Contents:

- `lab/` — private Tor network, Docker image, and laboratory scripts;
- `code/` — the English `torlab` educational client, tests, and reproducible fixtures;
- `wiki/` — English documentation for Laboratories 1–20.

The executable experiments must target **only the controlled private Chutney laboratory network**, never public Tor relays or third-party services. Docker with `--network host` shares the host's network namespace; use a controlled test host. `lab/net/` contains generated node identities, private keys and state and must not be published.

From the repository root:

```bash
make -C labs/en test
make -C labs/en image
make -C labs/en start
make -C labs/en verify
```

The corresponding Italian workflow is isolated under `labs/it/`.

## What the commands cover

- `make -C labs/en test` runs the local `torlab` unit tests; it **does not execute all 20 laboratory experiments**.
- `make -C labs/en verify` runs those unit tests and then Chutney's network check. The image and private network must already be configured; a successful result alone does not validate all exercise scripts.
- `make -C labs/en data` explicitly downloads historical public CollecTor data over HTTPS. The fetch script checks the **file header**, not consensus signatures or authority certificates.
- `make -C labs/en stop` stops the laboratory while preserving `lab/net/`; `make -C labs/en clean` **deletes `lab/net/`, including generated keys and identities**. Inspect the state before cleaning or changing topology.

For a shell, invoke `make -C labs/en/lab shell`. To use the 12-node obfs4 bridge topology, stop the ordinary network, inspect/remove only disposable state, then use `make -C labs/en/lab start NETWORK=book-bridge`. Unlike the 10-node `book` topology, the bridge topology has no onion service. Full setup and limitations: [laboratory README](lab/README.md).
