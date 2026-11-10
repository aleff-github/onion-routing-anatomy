# Laboratory Wiki

This wiki accompanies *Anatomy of Tor: The Anonymity Protocol, Byte by Byte*. It documents the book's **twenty laboratories**: what each demonstrates, what you need to run it, the exact commands, the expected output, and the problems encountered in practice. Code excerpts in these pages are simplified for reading and omit some validity checks: the reference is the code in `labs/en/code` and `labs/en/lab`.

The book explains *why*. This wiki helps you *make it work*.

> Network experiments use a private Tor topology and do not attack or measure public Tor users. Laboratory 2 runs offline; Laboratories 7, 15 and 19 work with historical public Tor documents that may need to be acquired separately. Those calculations do not send experimental traffic to public Tor users.

## Start here

1. [Installation](Installation.md) — requirements and setup from scratch.
2. [The laboratory network](Laboratory-network.md) — topology, ports, commands, and restarting an unresponsive network.
3. [Automated verification](Automated-verification.md) — separate Python tests, Chutney checks and laboratory-specific scripts, each with its own prerequisites.
4. [Troubleshooting](Troubleshooting.md) — practical problems and their causes.

## The twenty laboratories

| Lab | Chapter | Title | Network? |
|---:|---:|---|:---:|
| 1 | 7 | [Opening a verified channel](Laboratory-01-Channel.md) | Yes |
| 2 | 8 | [Encoding and decoding cells](Laboratory-02-Cells.md) | No |
| 3 | 9 | [Circuit handshake: ntor and ntor-v3](Laboratory-03-Handshake.md) | Yes |
| 4 | 10 | [Layered encryption and a three-hop circuit](Laboratory-04-Encryption.md) | Yes |
| 5 | 11 | [Downloading a file: streams, windows, and SENDME](Laboratory-05-Streams.md) | Yes |
| 6 | 12 | [Downloading and verifying the consensus](Laboratory-06-Directory.md) | Yes |
| 7 | 13 | [Bandwidth-weighted path selection](Laboratory-07-Path-selection.md) | No |
| 8 | 14 | [Finding and reading an onion descriptor](Laboratory-08-Onion-services.md) | Yes |
| 9 | 15 | [Triggering anti-DoS defenses](Laboratory-09-DoS.md) | Yes |
| 10 | 16 | [An obfs4 bridge through a censor's eyes](Laboratory-10-Bridge.md) | Separate network |
| 11 | 18 | [Live stream isolation](Laboratory-11-Isolation.md) | Yes |
| 12 | 20 | [Cells inside TLS](Laboratory-12-Traffic.md) | Yes |
| 13 | 21 | [An onion service with restricted discovery](Laboratory-13-Restricted-discovery.md) | Yes |
| 14 | 22 | [Testing an exit policy](Laboratory-14-Exit-policy.md) | Yes |
| 15 | 24 | [Network statistics from a consensus](Laboratory-15-Metrics.md) | No |
| 16 | 26 | [Correlating your own traffic](Laboratory-16-Correlation.md) | Yes |
| 17 | 27 | [The RELAY_EARLY cell limit](Laboratory-17-Relay-early.md) | Yes |
| 18 | 28 | [Tor detects a DNS-leak warning sign](Laboratory-18-DNS-leak.md) | Yes |
| 19 | 29 | [Time to first compromise](Laboratory-19-Simulation.md) | No |
| 20 | 30 | [Arti on the private network](Laboratory-20-Arti.md) | Yes |

Five introductory pages and twenty laboratory pages are present under `labs/en/wiki/`. The environment is organized under `labs/en/`.

Part II's laboratories (1–10) build `labs/en/code/torlab` incrementally and should be completed in order: each uses modules created in earlier laboratories. Later laboratories are independent.

## What each laboratory page contains

Each page describes what the experiment demonstrates, setup, exact commands, expected results with an explanation, automated verification, and known problems.

Laboratories 1–8, which progressively build the client, add an **Implementation, in detail** section. It explains every function step by step, the reasoning behind its design, mistakes worth avoiding, and a final table mapping each rule to the relevant passage in the specification. The book explains the protocol; these pages explain its implementation.

These outputs come from runs of the laboratory network with tor 0.4.9.13, the book's reference version. Keys, addresses and timing can differ; numerical results for Laboratories 7, 15 and 19 require the corresponding historical input data. For protocol-level differences, consult [troubleshooting](Troubleshooting.md) and repeat the relevant checks.
