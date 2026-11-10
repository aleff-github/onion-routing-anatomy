# Installation

Start here on a machine that has never used this repository.

## Requirements

| | Why you need it | How to check |
|---|---|---|
| **Docker** | Runs the entire laboratory network; also used for building the book | `docker run --rm hello-world` |
| **Python 3.11+** | The educational `torlab` client | `python3 --version` |
| **`cryptography`** | X25519, Ed25519 and AES | `python3 -c "import cryptography; print(cryptography.__version__)"` |
| **`pytest`** | Runs the local tests; the count is not fixed without execution | `python3 -m pytest --version` |
| **Rust (`cargo`)** | **Only** for Laboratory 20, which builds Arti | `cargo --version` |

```bash
python3 -m pip install -r requirements.txt
```

You do **not** need `stem` installed on the host: the three laboratories using it (11, 16, and 18) run inside the container, which already includes it.

Disk space: around **3 GB** for the Docker image, tor source code, and network state. Laboratory 20 requires approximately **2 GB** more to compile Arti.

Operating system: developed and tested on Linux. On macOS, Docker runs inside a virtual machine; `--network host` behaves differently from Linux, so the laboratory network needs adaptation, and the traffic-capture laboratories that use `lo` (10 and 12) will not work as written.

## Step 1: Build the image

```bash
make -C labs/en/lab image
```

This builds tor 0.4.9.13 from source inside the image, alongside Chutney, obfs4proxy, snowflake-client, `tshark`, and `curl`. **It takes several minutes** (around thirteen minutes without a cache on the machine used for the original tests) and downloads several hundred megabytes.

Why compile tor instead of installing your distribution's package?

- Its version is **pinned** in the Dockerfile (`ARG TOR_VERSION`), keeping the book's results reproducible over time.
- We need `--enable-gpl`, which enables the onion-service proof-of-work module (Laboratory 9, Chapter 15). The original installation instructions caution that distribution builds may omit this configuration; check your build rather than assuming.
- Having the source code readily available is part of the book's purpose: when specifications do not answer a question, examine the code under `src/core/or/`.

Check:

```bash
docker run --rm torbook-lab:latest tor --version
```

## Step 2: Start the network

```bash
make -C labs/en/lab start
```

This creates the `torbook-network` container, generates keys and configuration for ten nodes using Chutney, and waits for bootstrap. EN, RU and ZH-CN share the Docker image tag and container name; stop one edition's network before starting another. They cannot share host ports concurrently. On the source author's machine, this took approximately two minutes: authorities on the private network vote every 20 seconds, so the first consensus arrives quickly.

```bash
make -C labs/en/lab verify
```

Expected: `successes:4 failures:0`. Chutney sends trial traffic through the network and verifies end-to-end delivery.

For failures, consult [Troubleshooting](Troubleshooting.md).

## Step 3: Verify the laboratories

```bash
make -C labs/en test         # offline English Python suite
make -C labs/en/lab verify   # Chutney verification, network already running
```

Python tests and Chutney connectivity checks do not execute all twenty laboratory scenarios. For individual experiments consult [Automated Verification](Automated-verification.md). Labs 7, 15 and 19 require matching historical data; the original 53/53 figure is not a new test result.

Code tests that do not require the network:

```bash
PYTHONPATH=labs/en/code python3 -m pytest -q labs/en/code/torlab/test
```

These figures describe the original test environment. They are **not** claims that this English translation session reran the tests.

## Step 4 (optional): Build the book

```bash
make book-pdf     # builds book/it/anatomia-di-tor_it_A4.pdf using LaTeX inside Docker
```

You do not need LaTeX installed locally: this uses the `texlive/texlive` image, which initially downloads around 5 GB. This command builds the **Italian original**. The English edition's sources are in `source/en/`, and `make -C source/en pdf` builds it with LaTeX installed locally; see `docs/translations/en.md`.

## Stop the network

```bash
make -C labs/en/lab stop      # stop nodes but retain keys and data in labs/en/lab/net/
make -C labs/en/lab clean    # stop the network and delete labs/en/lab/net/
```

`labs/en/lab/net/` contains private keys for test nodes. It is not version-controlled and must not be published. These keys belong to a toy network, but good handling habits help avoid accidental publication of real keys.
